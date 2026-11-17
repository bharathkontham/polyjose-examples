"use client";

// The page's client side: one button per crossing, a button that runs the checks, and the
// operation log. With `?verify=1` in the URL the checks run as soon as the page has loaded.
// polyjose runs only in event handlers and effects here, never while the server renders.
import { useCallback, useEffect, useRef, useState } from "react";

import { CHECKS, runChecks } from "../lib/browser/checks";
import {
  TapLog,
  browserEncryptsServerDecrypts,
  browserSignsServerVerifies,
  serverEncryptsBrowserDecrypts,
  serverIssuesBrowserVerifies,
  type Outcome,
} from "../lib/browser/crossings";

interface Crossing {
  readonly label: string;
  readonly run: (log: TapLog) => Promise<Outcome<unknown>>;
}

const CROSSINGS: readonly Crossing[] = [
  { label: "Browser signs, server verifies (ES256)", run: (log) => browserSignsServerVerifies(log) },
  { label: "Server issues a JWT, browser verifies it with the JWKS", run: serverIssuesBrowserVerifies },
  { label: "Browser encrypts, server decrypts (P-256)", run: browserEncryptsServerDecrypts },
  { label: "Server encrypts, browser decrypts (P-256)", run: serverEncryptsBrowserDecrypts },
];

export default function Playground() {
  const [result, setResult] = useState("");
  const [log, setLog] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const nextTap = useRef(1);
  const started = useRef(false);

  /** One log line: on the page and in the browser console. */
  const sink = useCallback((line: string) => {
    console.log(line);
    setLog((lines) => [...lines, line]);
  }, []);

  const checks = useCallback(async () => {
    setBusy(true);
    setResult("");
    const firstTap = nextTap.current;
    nextTap.current += CHECKS.length;
    await runChecks(
      (line) => {
        console.log(line);
        setResult((text) => `${text}${line}\n`);
      },
      sink,
      firstTap,
    );
    setBusy(false);
  }, [sink]);

  const cross = useCallback(
    async (crossing: Crossing) => {
      setBusy(true);
      const log = new TapLog(nextTap.current++, sink);
      const outcome = await crossing.run(log);
      log.step(outcome.ok ? "done" : "refused", outcome.ok ? { result: "ok" } : { side: outcome.side, code: outcome.code });
      setBusy(false);
    },
    [sink],
  );

  useEffect(() => {
    if (started.current) return; // React runs effects twice in development
    started.current = true;
    if (new URLSearchParams(window.location.search).get("verify") === "1") void checks();
  }, [checks]);

  return (
    <>
      <section aria-labelledby="crossings">
        <h2 id="crossings">Crossings</h2>
        <div className="buttons">
          {CROSSINGS.map((crossing) => (
            <button key={crossing.label} type="button" disabled={busy} onClick={() => void cross(crossing)}>
              {crossing.label}
            </button>
          ))}
        </div>
      </section>
      <section aria-labelledby="checks">
        <h2 id="checks">Checks</h2>
        <button type="button" disabled={busy} onClick={() => void checks()}>
          Run the checks
        </button>
        <pre id="result">{result}</pre>
      </section>
      <section aria-labelledby="log">
        <h2 id="log">Log</h2>
        <button type="button" onClick={() => setLog([])}>
          Clear
        </button>
        <pre id="log-lines">{log.join("\n")}</pre>
      </section>
    </>
  );
}
