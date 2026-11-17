"use client";

// The Encrypt tab: the key-management `alg`, the curve (ECDH-ES), the `enc`, the key store that
// decrypts, the key, Encrypt / Decrypt / Round trip, the failure actions and the result card.
import { useState } from "react";

import { ECDH_CURVES, ENCRYPT_FAILURES, ENCRYPT_ROWS, ENCS, PAYLOAD, STORES, failureDisabled, type EcdhCurve, type EncryptRow } from "../lib/matrix";
import { explain } from "../lib/explanations";
import { encryptFailureTap, encryptTap, type Card, type Encrypted } from "../lib/browser/playground";
import type { SoftwareKey } from "../lib/browser/polyjose";
import type { Tapper } from "./Playground";
import { Choice, Info, ResultCard, Text } from "./ui";

/** Whether a Keys-tab key fits the chosen row, curve and `enc`. */
function fits(key: SoftwareKey, row: EncryptRow, crv: EcdhCurve, enc: string): boolean {
  if (key.alg !== row.alg) return false;
  if (row.kind === "ecdh") return key.crv === crv;
  if (row.kind === "dir") return key.enc === enc;
  return true;
}

export default function EncryptTab({ tap, busy, session }: { tap: Tapper; busy: boolean; session: readonly SoftwareKey[] }) {
  const [alg, setAlg] = useState("ECDH-ES+A256KW");
  const [crv, setCrv] = useState<EcdhCurve>("P-256");
  const [enc, setEnc] = useState<string>("A256GCM");
  const [keyKid, setKeyKid] = useState("new");
  const [card, setCard] = useState<Card | null>(null);
  const [encrypted, setEncrypted] = useState<Encrypted | undefined>();

  const row = ENCRYPT_ROWS.find((r) => r.alg === alg) as EncryptRow;
  const keys = session.filter((key) => fits(key, row, crv, enc));
  const key = keys.find((k) => k.kid === keyKid);
  const spec = { row, enc, crv: row.kind === "ecdh" ? crv : undefined, key };
  const canDecrypt = encrypted !== undefined && encrypted.alg === alg && encrypted.enc === enc;

  const run = (mode: "encrypt" | "decrypt" | "round-trip") =>
    void tap(async (log) => {
      const result = await encryptTap(log, spec, mode, encrypted);
      setCard(result.card);
      if (result.encrypted) setEncrypted(result.encrypted);
    });

  return (
    <div>
      <p className="explain">
        <Text text={explain("tab.encrypt")} />
      </p>
      <Choice
        name="encrypt-alg"
        legend="Key management alg"
        options={ENCRYPT_ROWS.map((r) => ({ value: r.alg, label: r.kind === "rsa" ? `${r.alg} (test key)` : r.alg }))}
        value={alg}
        onChange={(value) => {
          setAlg(value);
          setKeyKid("new");
        }}
        info={(value) => `alg.${value}`}
      />
      {row.kind === "ecdh" && (
        <Choice name="encrypt-crv" legend="Curve" options={ECDH_CURVES.map((c) => ({ value: c, label: c }))} value={crv} onChange={setCrv} info={(c) => `crv.${c}`} />
      )}
      {row.kind === "rsa" && (
        <p className="explain">
          RSA size: 2048 bits. <Text text={explain("key.test-rsa")} />
        </p>
      )}
      {row.kind === "pbes2" && (
        <p className="explain">
          <Text text={explain("key.password")} />
        </p>
      )}
      <Choice name="encrypt-enc" legend="Content encryption (enc)" options={ENCS.map((e) => ({ value: e, label: e }))} value={enc} onChange={setEnc} info={(e) => `enc.${e}`} />
      <Choice
        name="encrypt-store"
        legend="Key store that decrypts"
        options={STORES.map((s) => ({ value: s.id, label: s.label, disabled: s.disabled }))}
        value="software"
        onChange={() => undefined}
        info={(id) => `store.${id}`}
      />
      <Choice
        name="encrypt-key"
        legend="Key"
        options={[
          { value: "new", label: row.kind === "rsa" ? "The RFC 7515 A.2 test key" : "A new key" },
          ...keys.map((k) => ({ value: k.kid, label: `Keys tab: ${k.alg} ${k.kid.slice(0, 12)}` })),
        ]}
        value={key ? key.kid : "new"}
        onChange={setKeyKid}
      />
      <p>
        Plaintext: <code>{PAYLOAD}</code> <Info id="option.payload" label="the plaintext" />
      </p>
      <div className="buttons">
        <button type="button" disabled={busy} onClick={() => run("encrypt")}>
          Encrypt
        </button>
        <button type="button" disabled={busy || !canDecrypt} onClick={() => run("decrypt")}>
          Decrypt
        </button>
        <button type="button" disabled={busy} onClick={() => run("round-trip")}>
          Round trip
        </button>
      </div>
      <fieldset>
        <legend>Try a failure</legend>
        <p className="explain">
          <Text text={explain("note.decrypt-failures")} />
        </p>
        <div className="buttons">
          {ENCRYPT_FAILURES.map((action) => {
            const disabled = failureDisabled(action, row);
            return (
              <span key={action.id} className="choice">
                <button
                  type="button"
                  disabled={busy || disabled !== undefined}
                  title={disabled ? explain(disabled) : `Ends with ${action.code}`}
                  onClick={() =>
                    void tap(async (log) => {
                      setCard((await encryptFailureTap(log, spec, action)).card);
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
