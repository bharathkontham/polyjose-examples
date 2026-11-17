"use client";

// The demo walk (`/?demo=1`, PLAYGROUND.md "Demo walk"): every cell of the support matrix and
// every failure action, through the same functions the tabs' buttons call, one tap each. A ✓
// cell must succeed; a failure action must end with its code. Then the Server tab's crossings
// and refusals, the Keys tab, and the secrets check over the walk's own log (member names, and
// the private values of every key the walk made). It prints
//
//   PLAYGROUND ok sign/jws/ES256
//   PLAYGROUND bad encrypt/A128KW/A256GCM: expected success, got InvalidKey
//   POLYJOSE-PLAYGROUND: 329/330 OK
//
// The disabled rows (platform key store, WebCrypto non-extractable key, the deleted-key actions)
// have no call to make, so the walk doesn't count them.
import {
  ECDH_CURVES,
  ENCRYPT_FAILURES,
  ENCRYPT_ROWS,
  ENCS,
  SERVER_ACTIONS,
  SIGN_FAILURES,
  SIGN_ROWS,
  failureDisabled,
  type EcdhCurve,
} from "../matrix";
import { SECRET_LINE, joinLogEntries } from "../shared";
import {
  asExpected,
  encryptFailureTap,
  encryptTap,
  keyCreateTap,
  keyDeleteTap,
  keyShowTap,
  serverTap,
  signFailureTap,
  signTap,
  type Card,
} from "./playground";
import { startKeyRecorder, type KeyRecorder } from "./polyjose";
import { TapLog, codeOf, type LogSink } from "./tap-log";

/** A step's outcome: whether it was the expected one, and what was expected and seen. */
interface Seen {
  readonly ok: boolean;
  readonly expected: string;
  readonly got: string;
}

interface WalkStep {
  readonly id: string;
  readonly run: (log: TapLog) => Promise<Seen>;
}

function seen(card: Card): Seen {
  return { ok: asExpected(card), expected: card.expected ?? "success", got: card.outcome.ok ? "success" : card.outcome.code };
}

const yes = (ok: boolean, expected: string, got: string): Seen => ({ ok, expected, got });

/** The curves of a row: four for ECDH-ES, none for the others. */
function curves(kind: string): readonly (EcdhCurve | undefined)[] {
  return kind === "ecdh" ? ECDH_CURVES : [undefined];
}

/**
 * Every step, in order. `logged` is every line the walk has logged so far; `recorder` holds the
 * private member values of every key made during the walk (absent when only counting steps).
 */
function walkSteps(logged: readonly string[], recorder?: KeyRecorder): WalkStep[] {
  const steps: WalkStep[] = [];
  const add = (id: string, run: (log: TapLog) => Promise<Seen>) => steps.push({ id, run });

  // Sign: every algorithm, JWS and JWT, then every failure action of each.
  for (const row of SIGN_ROWS) {
    for (const op of ["jws", "jwt"] as const) add(`sign/${op}/${row.alg}`, async (log) => seen((await signTap(log, { op, row }, "sign-verify")).card));
  }
  for (const row of SIGN_ROWS) {
    for (const action of SIGN_FAILURES) {
      if (failureDisabled(action, row)) continue;
      add(`sign/${row.alg}/${action.id}`, async (log) => seen((await signFailureTap(log, { op: "jws", row }, action)).card));
    }
  }

  // Encrypt: every alg (on every curve) with every enc, then every failure action of each.
  for (const row of ENCRYPT_ROWS) {
    for (const crv of curves(row.kind)) {
      for (const enc of ENCS) {
        const id = `encrypt/${row.alg}${crv ? `/${crv}` : ""}/${enc}`;
        add(id, async (log) => seen((await encryptTap(log, { row, enc, crv }, "round-trip")).card));
      }
    }
  }
  for (const row of ENCRYPT_ROWS) {
    for (const crv of curves(row.kind)) {
      for (const action of ENCRYPT_FAILURES) {
        if (failureDisabled(action, row)) continue;
        const id = `encrypt/${row.alg}${crv ? `/${crv}` : ""}/${action.id}`;
        add(id, async (log) => seen((await encryptFailureTap(log, { row, enc: "A256GCM", crv }, action)).card));
      }
    }
  }

  // Sign, then Verify as a second tap; Encrypt, then Decrypt.
  const es256 = SIGN_ROWS.find((row) => row.alg === "ES256");
  const ecdh = ENCRYPT_ROWS.find((row) => row.alg === "ECDH-ES+A256KW");
  if (es256) {
    add("sign/verify-again/ES256", async (log) => {
      const first = await signTap(log, { op: "jws", row: es256 }, "sign");
      return seen((await signTap(log, { op: "jws", row: es256 }, "verify", first.signed)).card);
    });
  }
  if (ecdh) {
    add("encrypt/decrypt-again/ECDH-ES+A256KW", async (log) => {
      const spec = { row: ecdh, enc: "A256GCM", crv: "P-256" as const };
      const first = await encryptTap(log, spec, "encrypt");
      return seen((await encryptTap(log, spec, "decrypt", first.encrypted)).card);
    });
  }

  // Keys: create a key, show its public JWK and thumbprint, sign with it, delete it.
  if (es256) {
    add("keys/es256/create-show-sign-delete", async (log) => {
      const key = await keyCreateTap(log, { kind: "EC", alg: "ES256" });
      if (!key) return yes(false, "success", "no key");
      const detail = await keyShowTap(log, key);
      if (detail.thumbprint !== key.kid) return yes(false, "thumbprint = kid", "thumbprint differs");
      const signed = await signTap(log, { op: "jwt", row: es256, key }, "sign-verify");
      keyDeleteTap(log, [key]);
      return seen(signed.card);
    });
  }
  add("keys/hs256/shared-key-has-no-public-jwk", async (log) => {
    const key = await keyCreateTap(log, { kind: "oct", alg: "HS256" });
    if (!key) return yes(false, "success", "no key");
    const detail = await keyShowTap(log, key);
    keyDeleteTap(log, [key]);
    return yes(detail.jwk === null && detail.thumbprint === null, "no public JWK", detail.jwk === null ? "no public JWK" : "a JWK");
  });

  // Server: the four crossings and the server's four refusals.
  for (const action of SERVER_ACTIONS) {
    add(`server/${action.id}`, async (log) => seen(await serverTap(log, action.id, action.label, "code" in action ? action.code : undefined)));
  }

  // Secrets (PLAYGROUND.md, "Secrets"): no entry the walk logged (continuation parts joined back)
  // has a private or symmetric member as JSON, or the value of a private member of any key the
  // walk made. Counts only, never a line or a value.
  add("secrets/walk-log-has-no-private-member", async (log) => {
    const entries = joinLogEntries(logged);
    const members = entries.filter((entry) => SECRET_LINE.test(entry)).length;
    const values = recorder ? recorder.matches(entries) : 0;
    const recorded = recorder ? recorder.size : 0;
    const matches = members + values;
    log.step("secrets", { lines: logged.length, matches });
    if (recorded === 0) return yes(false, "0 matches", "no key values recorded");
    return yes(matches === 0, "0 matches", `${members} member and ${values} value matches`);
  });
  return steps;
}

/** The number of steps the walk has. */
export function walkLength(): number {
  return walkSteps([]).length;
}

/**
 * Runs the walk: one tap per step from `firstTap`, its lines to `log`, and its result lines
 * to `out` (the page and the console), ending with `POLYJOSE-PLAYGROUND: N/M OK`.
 */
export async function runWalk(out: (line: string) => void, log: LogSink, firstTap: number): Promise<{ ok: number; walked: number }> {
  const logged: string[] = [];
  const sink: LogSink = (line) => {
    logged.push(line);
    log(line);
  };
  // Only the walk switches the key recorder on, and it is off again when the walk ends.
  const recorder = startKeyRecorder();
  const steps = walkSteps(logged, recorder);
  out(`# polyjose playground demo walk: ${steps.length} steps, every one through the tabs' code`);
  let ok = 0;
  try {
    for (const [index, step] of steps.entries()) {
      let result: Seen;
      try {
        result = await step.run(new TapLog(firstTap + index, sink));
      } catch (err) {
        result = yes(false, "success", `unexpected ${codeOf(err)}`);
      }
      if (result.ok) ok += 1;
      out(result.ok ? `PLAYGROUND ok ${step.id}` : `PLAYGROUND bad ${step.id}: expected ${result.expected}, got ${result.got}`);
    }
  } finally {
    recorder.stop();
  }
  out(`POLYJOSE-PLAYGROUND: ${ok}/${steps.length} OK`);
  return { ok, walked: steps.length };
}
