"use client";

// The Sign tab: JWS compact or JWT, the key store, one row per algorithm, the key, the fixed
// payload, Sign / Verify / Sign and verify, the failure actions and the result card.
import { useState } from "react";

import { JWT_CLAIMS, PAYLOAD, SIGN_FAILURES, SIGN_ROWS, STORES, failureDisabled, type SignRow } from "../lib/matrix";
import { explain } from "../lib/explanations";
import { signFailureTap, signTap, type Card, type SignOp, type Signed } from "../lib/browser/playground";
import type { SoftwareKey } from "../lib/browser/polyjose";
import type { Tapper } from "./Playground";
import { Choice, Info, ResultCard, Text } from "./ui";

const OPS = [
  { value: "jws", label: "JWS compact" },
  { value: "jwt", label: "JWT" },
] as const;

export default function SignTab({ tap, busy, session }: { tap: Tapper; busy: boolean; session: readonly SoftwareKey[] }) {
  const [op, setOp] = useState<SignOp>("jws");
  const [alg, setAlg] = useState("ES256");
  const [keyKid, setKeyKid] = useState("new");
  const [card, setCard] = useState<Card | null>(null);
  const [signed, setSigned] = useState<Signed | undefined>();

  const row = SIGN_ROWS.find((r) => r.alg === alg) as SignRow;
  const keys = session.filter((key) => key.alg === alg);
  const key = keys.find((k) => k.kid === keyKid);
  const spec = { op, row, key };
  const canVerify = signed !== undefined && signed.alg === alg && signed.op === op;

  const run = (mode: "sign" | "verify" | "sign-verify") =>
    void tap(async (log) => {
      const result = await signTap(log, spec, mode, signed);
      setCard(result.card);
      if (result.signed) setSigned(result.signed);
    });

  return (
    <div>
      <p className="explain">
        <Text text={explain("tab.sign")} />
      </p>
      <Choice name="sign-op" legend="Operation" options={OPS} value={op} onChange={setOp} />
      <Choice
        name="sign-store"
        legend="Key store"
        options={STORES.map((s) => ({ value: s.id, label: s.label, disabled: s.disabled }))}
        value="software"
        onChange={() => undefined}
        info={(id) => `store.${id}`}
      />
      <Choice
        name="sign-alg"
        legend="Algorithm"
        options={SIGN_ROWS.map((r) => ({ value: r.alg, label: r.kind === "RSA" ? `${r.alg} (test key)` : r.alg }))}
        value={alg}
        onChange={(value) => {
          setAlg(value);
          setKeyKid("new");
        }}
        info={(value) => `alg.${value}`}
      />
      <Choice
        name="sign-key"
        legend="Key"
        options={[
          { value: "new", label: row.kind === "RSA" ? "The RFC 7515 A.2 test key" : "A new key" },
          ...keys.map((k) => ({ value: k.kid, label: `Keys tab: ${k.alg} ${k.kid.slice(0, 12)}` })),
        ]}
        value={key ? key.kid : "new"}
        onChange={setKeyKid}
      />
      {row.kind === "RSA" && (
        <p className="explain">
          <Text text={explain("key.test-rsa")} />
        </p>
      )}
      <p>
        Payload: {op === "jws" ? <code>{PAYLOAD}</code> : <code>{JSON.stringify({ ...JWT_CLAIMS, exp: "now + 300 s" })}</code>}{" "}
        <Info id="option.payload" label="the payload" />
      </p>
      <div className="buttons">
        <button type="button" disabled={busy} onClick={() => run("sign")}>
          Sign
        </button>
        <button type="button" disabled={busy || !canVerify} onClick={() => run("verify")}>
          Verify
        </button>
        <button type="button" disabled={busy} onClick={() => run("sign-verify")}>
          Sign and verify
        </button>
      </div>
      <fieldset>
        <legend>Try a failure</legend>
        <div className="buttons">
          {SIGN_FAILURES.map((action) => {
            const disabled = failureDisabled(action, row);
            return (
              <span key={action.id} className="choice">
                <button
                  type="button"
                  disabled={busy || disabled !== undefined}
                  title={disabled ? explain(disabled) : `Ends with ${action.code}`}
                  onClick={() =>
                    void tap(async (log) => {
                      setCard((await signFailureTap(log, spec, action)).card);
                    })
                  }
                >
                  {action.label} → {action.code}
                </button>
                {disabled && <span className="reason"> {explain(disabled)}</span>}
                <Info id={action.id} label={action.label} />
              </span>
            );
          })}
        </div>
      </fieldset>
      <ResultCard card={card} />
    </div>
  );
}
