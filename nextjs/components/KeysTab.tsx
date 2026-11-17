"use client";

// The Keys tab: this browser's capabilities, the key stores (two disabled, with the reason) and
// the session's software keys. A key's detail shows its public JWK (through the publicOnly gate)
// and its RFC 7638 thumbprint; a shared key shows its length only. Delete drops the key.
import { useState } from "react";

import { ECDH_CURVES, ENCRYPT_ROWS, ENCS, SIGN_ROWS, STORES, type EcdhCurve } from "../lib/matrix";
import { explain } from "../lib/explanations";
import { keyCreateTap, keyDeleteTap, keyShowTap, type Device, type KeyDetail } from "../lib/browser/playground";
import type { KeyRequest, SoftwareKey } from "../lib/browser/polyjose";
import type { Tapper } from "./Playground";
import { publicOnly } from "../lib/shared";
import { Choice, CopyButton, Info, Json, Text } from "./ui";

/** Every row a key can be made for: the JWS algorithms, then the JWE key-management algorithms. */
const ROWS = [
  ...SIGN_ROWS.map((row) => ({ value: `sig:${row.alg}`, label: row.alg, kind: row.kind, alg: row.alg })),
  ...ENCRYPT_ROWS.map((row) => ({ value: `enc:${row.alg}`, label: row.alg, kind: row.kind, alg: row.alg })),
];

function describe(key: SoftwareKey): string {
  const parts = [key.alg, key.kty, key.crv, key.enc && `for ${key.enc}`, key.bits && `${key.bits} bits`, key.testKey && "RFC 7515 A.2 test key"];
  return parts.filter(Boolean).join(" · ");
}

function KeyRow({ keyItem, tap, busy, onDelete }: { keyItem: SoftwareKey; tap: Tapper; busy: boolean; onDelete: () => void }) {
  const [detail, setDetail] = useState<KeyDetail | null>(null);
  return (
    <li>
      <p>
        <strong>{describe(keyItem)}</strong>
        <br />
        <code>kid {keyItem.kid}</code>
      </p>
      <div className="buttons">
        <button type="button" disabled={busy} onClick={() => void tap(async (log) => setDetail(await keyShowTap(log, keyItem)))}>
          Show public JWK and thumbprint
        </button>
        <button type="button" disabled={busy} onClick={onDelete}>
          Delete
        </button>
      </div>
      {detail &&
        (detail.jwk ? (
          <>
            <Json value={detail.jwk} />
            <CopyButton text={JSON.stringify(publicOnly(detail.jwk))} label="Copy public JWK" />
            <p>
              RFC 7638 thumbprint (SHA-256): <code>{detail.thumbprint ?? "not available"}</code>
            </p>
          </>
        ) : (
          <p className="explain">A shared key has no public half: it is shown as its type, algorithm, kid and length only.</p>
        ))}
    </li>
  );
}

export default function KeysTab({
  tap,
  busy,
  device,
  session,
  setSession,
}: {
  tap: Tapper;
  busy: boolean;
  device: Device | null;
  session: readonly SoftwareKey[];
  setSession: (update: (keys: readonly SoftwareKey[]) => readonly SoftwareKey[]) => void;
}) {
  const [choice, setChoice] = useState("sig:ES256");
  const [crv, setCrv] = useState<EcdhCurve>("P-256");
  const [enc, setEnc] = useState<string>("A256GCM");
  const row = ROWS.find((r) => r.value === choice) ?? ROWS[0];

  const create = () =>
    void tap(async (log) => {
      if (!row) return;
      const request: KeyRequest = { kind: row.kind, alg: row.alg, crv: row.kind === "ecdh" ? crv : undefined, enc: row.kind === "dir" ? enc : undefined };
      const key = await keyCreateTap(log, request);
      if (key) setSession((keys) => [...keys, key]);
    });

  const remove = (keys: readonly SoftwareKey[]) =>
    void tap(async (log) => {
      keyDeleteTap(log, keys);
      const gone = new Set(keys);
      setSession((all) => all.filter((key) => !gone.has(key)));
    });

  return (
    <div>
      <p className="explain">
        <Text text={explain("tab.keys")} />
      </p>
      <section className="card">
        <h3>This browser</h3>
        {device ? (
          <ul>
            <li>polyjose {device.polyjose} through @polyjose/wasm</li>
            <li>{device.browser}</li>
            <li>Secure context: {device.secureContext ? "yes" : "no"}</li>
            <li>WebCrypto: {device.webCrypto ? "present, but polyjose 0.4.0 doesn't use CryptoKey objects" : "absent"}</li>
            <li>Platform key store: not in polyjose 0.4.0</li>
          </ul>
        ) : (
          <p>Loading…</p>
        )}
        <p className="explain">
          <Text text={explain("note.browser")} />
        </p>
      </section>
      <h3>Key stores</h3>
      <ul className="stores">
        {STORES.map((store) => (
          <li key={store.id} className={store.disabled ? "disabled" : undefined}>
            {store.label}
            {store.disabled && <span className="reason"> — {explain(store.disabled)}</span>} <Info id={`store.${store.id}`} label={store.label} />
          </li>
        ))}
      </ul>
      <h3>Create a software key</h3>
      <Choice name="keys-alg" legend="Algorithm" options={ROWS.map((r) => ({ value: r.value, label: r.label }))} value={choice} onChange={setChoice} />
      {row?.kind === "ecdh" && <Choice name="keys-crv" legend="Curve" options={ECDH_CURVES.map((c) => ({ value: c, label: c }))} value={crv} onChange={setCrv} />}
      {row?.kind === "dir" && <Choice name="keys-enc" legend="For enc" options={ENCS.map((e) => ({ value: e, label: e }))} value={enc} onChange={setEnc} />}
      <div className="buttons">
        <button type="button" disabled={busy} onClick={create}>
          Create key
        </button>
        <button type="button" disabled={busy || session.length === 0} onClick={() => remove(session)}>
          Delete all playground keys
        </button>
      </div>
      <h3>Software keys in this page ({session.length})</h3>
      {session.length === 0 ? (
        <p>None yet. The Sign and Encrypt tabs make a new key for each tap unless you pick one of these.</p>
      ) : (
        <ul className="keys">
          {session.map((key, i) => (
            <KeyRow key={`${i}-${key.kid}`} keyItem={key} tap={tap} busy={busy} onDelete={() => remove([key])} />
          ))}
        </ul>
      )}
    </div>
  );
}
