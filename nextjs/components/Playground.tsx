"use client";

// The page's client side: the playground's tabs (Checks, Sign, Encrypt, Server, Keys, Log), the
// operation log and the session's software keys. polyjose runs only in event handlers and
// effects here, never while the server renders.
//
// - `?verify=1` runs the checks as soon as the page has loaded: `POLYJOSE-VERIFY: 8/8 PASS`.
// - `?demo=1` runs the demo walk through the tabs' code: `POLYJOSE-PLAYGROUND: N/N OK`.
// Both may be given; the checks run first. Every log line is also written to the console.
import { useCallback, useEffect, useRef, useState } from "react";

import { CHECKS, runChecks } from "../lib/browser/checks";
import { runWalk, walkLength } from "../lib/browser/demo";
import { deviceTap, type Device } from "../lib/browser/playground";
import type { SoftwareKey } from "../lib/browser/polyjose";
import { TapLog } from "../lib/browser/tap-log";
import { explain } from "../lib/explanations";
import EncryptTab from "./EncryptTab";
import KeysTab from "./KeysTab";
import LogTab from "./LogTab";
import ServerTab from "./ServerTab";
import SignTab from "./SignTab";
import { Text } from "./ui";

/** Runs one tap: a fresh TapLog with the next tap number, the buttons disabled meanwhile. */
export type Tapper = (work: (log: TapLog) => Promise<void>) => Promise<void>;

const TABS = [
  { id: "checks", label: "Checks" },
  { id: "sign", label: "Sign" },
  { id: "encrypt", label: "Encrypt" },
  { id: "server", label: "Server" },
  { id: "keys", label: "Keys" },
  { id: "log", label: "Log" },
] as const;
type TabId = (typeof TABS)[number]["id"];

export default function Playground() {
  const [tab, setTab] = useState<TabId>("checks");
  const [busy, setBusy] = useState(false);
  const [device, setDevice] = useState<Device | null>(null);
  const [session, setSession] = useState<readonly SoftwareKey[]>([]);
  const [checkLines, setCheckLines] = useState("");
  const [walkLines, setWalkLines] = useState("");
  const [lines, setLines] = useState<readonly string[]>([]);
  const pending = useRef<string[]>([]);
  const flush = useRef<number | null>(null);
  const nextTap = useRef(1);
  const started = useRef(false);

  /**
   * One log line: to the browser console at once, and to the Log tab on the next animation frame
   * (a demo walk logs thousands of lines; one render per line would stall the page).
   */
  const sink = useCallback((line: string) => {
    console.log(line);
    pending.current.push(line);
    flush.current ??= requestAnimationFrame(() => {
      flush.current = null;
      const added = pending.current;
      pending.current = [];
      setLines((all) => [...all, ...added]);
    });
  }, []);

  const tap: Tapper = useCallback(
    async (work) => {
      setBusy(true);
      try {
        await work(new TapLog(nextTap.current++, sink));
      } finally {
        setBusy(false);
      }
    },
    [sink],
  );

  const checks = useCallback(async () => {
    setBusy(true);
    setCheckLines("");
    const firstTap = nextTap.current;
    nextTap.current += CHECKS.length;
    await runChecks(
      (line) => {
        console.log(line);
        setCheckLines((text) => `${text}${line}\n`);
      },
      sink,
      firstTap,
    );
    setBusy(false);
  }, [sink]);

  const walk = useCallback(async () => {
    setBusy(true);
    setWalkLines("");
    let text = "";
    const firstTap = nextTap.current;
    nextTap.current += walkLength();
    await runWalk(
      (line) => {
        console.log(line);
        text += `${line}\n`;
      },
      sink,
      firstTap,
    );
    setWalkLines(text);
    setBusy(false);
  }, [sink]);

  useEffect(() => {
    if (started.current) return; // React runs effects twice in development
    started.current = true;
    const params = new URLSearchParams(window.location.search);
    void (async () => {
      setDevice(await deviceTap(new TapLog(0, sink)));
      if (params.get("verify") === "1") await checks();
      if (params.get("demo") === "1") await walk();
    })();
  }, [checks, walk, sink]);

  return (
    <>
      <p className="note" role="note">
        <Text text={explain("note.browser")} />
      </p>
      <div role="tablist" aria-label="Playground" className="tabs">
        {TABS.map((t) => (
          <button key={t.id} type="button" role="tab" id={`tab-${t.id}`} aria-selected={tab === t.id} aria-controls={`panel-${t.id}`} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>
      <section role="tabpanel" id="panel-checks" aria-labelledby="tab-checks" hidden={tab !== "checks"}>
        <p className="explain">
          <Text text={explain("tab.checks")} />
        </p>
        <div className="buttons">
          <button type="button" disabled={busy} onClick={() => void checks()}>
            Run the checks
          </button>
          <button type="button" disabled={busy} onClick={() => void walk()}>
            Run the demo walk
          </button>
        </div>
        <pre id="result">{checkLines}</pre>
        <pre id="demo-result">{walkLines}</pre>
      </section>
      <section role="tabpanel" id="panel-sign" aria-labelledby="tab-sign" hidden={tab !== "sign"}>
        <SignTab tap={tap} busy={busy} session={session} />
      </section>
      <section role="tabpanel" id="panel-encrypt" aria-labelledby="tab-encrypt" hidden={tab !== "encrypt"}>
        <EncryptTab tap={tap} busy={busy} session={session} />
      </section>
      <section role="tabpanel" id="panel-server" aria-labelledby="tab-server" hidden={tab !== "server"}>
        <ServerTab tap={tap} busy={busy} />
      </section>
      <section role="tabpanel" id="panel-keys" aria-labelledby="tab-keys" hidden={tab !== "keys"}>
        <KeysTab tap={tap} busy={busy} device={device} session={session} setSession={setSession} />
      </section>
      <section role="tabpanel" id="panel-log" aria-labelledby="tab-log" hidden={tab !== "log"}>
        {tab === "log" && <LogTab lines={lines} onClear={() => setLines([])} />}
      </section>
    </>
  );
}
