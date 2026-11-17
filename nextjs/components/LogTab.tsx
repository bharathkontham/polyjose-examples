"use client";

// The Log tab: every step of every tap, newest tap first, one group per tap. Copy all
// (`navigator.clipboard`), Share (`navigator.share` where the browser has it, else a download of a
// `.txt` file) and Clear. The lines hold no secrets (PLAYGROUND.md, "Secrets"), so they can be
// shared as they are.
import { useMemo, useState } from "react";

import { explain } from "../lib/explanations";
import { Text } from "./ui";

interface Group {
  readonly tap: string;
  readonly title: string;
  readonly lines: string[];
}

/** The group title of a tap, from its first line: `#7 jws-sign-verify ES256 · software`. */
function title(tap: string, first: string): string {
  const field = (name: string) => first.match(new RegExp(` ${name}=(\\S+)`))?.[1];
  const event = first.split(" ")[2] ?? "";
  if (event === "device") return `#${tap} device`;
  const crossing = field("crossing");
  const parts = [field("op"), crossing, field("alg"), field("enc"), field("crv"), field("failure") && `failure ${field("failure")}`].filter(Boolean);
  return `#${tap} ${parts.join(" ")}${field("store") ? ` · ${field("store")}` : ""}`;
}

/** The lines grouped by tap (`LOG <tap>.<step>`), newest tap first. */
function groups(lines: readonly string[]): Group[] {
  const byTap = new Map<string, Group>();
  for (const line of lines) {
    const tap = line.match(/^LOG (\d+)\./)?.[1] ?? "?";
    let group = byTap.get(tap);
    if (!group) {
      group = { tap, title: title(tap, line), lines: [] };
      byTap.set(tap, group);
    }
    group.lines.push(line);
  }
  return [...byTap.values()].reverse();
}

const FILE_NAME = "polyjose-playground-log.txt";

/** Saves `text` as a `.txt` file through a temporary link. */
function download(text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = FILE_NAME;
  link.click();
  URL.revokeObjectURL(url);
}

export default function LogTab({ lines, onClear }: { lines: readonly string[]; onClear: () => void }) {
  const [state, setState] = useState("");
  const text = useMemo(() => `${lines.join("\n")}\n`, [lines]);
  const shown = useMemo(() => groups(lines), [lines]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setState(`copied ${lines.length} lines`);
    } catch (err) {
      setState(`not copied (${err instanceof Error ? err.name : "error"})`);
    }
  };

  const share = async () => {
    if (typeof navigator.share === "function") {
      try {
        await navigator.share({ title: "polyjose playground log", text });
        setState("shared");
        return;
      } catch (err) {
        if (err instanceof Error && err.name === "AbortError") {
          setState("not shared");
          return;
        }
        // The browser has Share but refused this text (too long, not allowed): download instead.
      }
    }
    download(text);
    setState(`saved ${FILE_NAME}`);
  };

  return (
    <div>
      <p className="explain">
        <Text text={explain("tab.log")} />
      </p>
      <div className="buttons">
        <button type="button" disabled={lines.length === 0} onClick={() => void copy()}>
          Copy all
        </button>
        <button type="button" disabled={lines.length === 0} onClick={() => void share()}>
          Share
        </button>
        <button
          type="button"
          disabled={lines.length === 0}
          onClick={() => {
            onClear();
            setState("cleared");
          }}
        >
          Clear
        </button>
        {state && <span role="status">{state}</span>}
      </div>
      <p>
        {lines.length} lines. Copy and Share give them oldest first, as the browser console and the server&apos;s output show them.
      </p>
      {shown.map((group) => (
        <details key={group.tap} open={shown.length <= 20}>
          <summary>{group.title}</summary>
          <pre className="mono">{group.lines.join("\n")}</pre>
        </details>
      ))}
    </div>
  );
}
