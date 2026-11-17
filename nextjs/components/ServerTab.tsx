"use client";

// The Server tab: the four crossings between this page and the route handlers, and the
// server's four refusals, one button each. The log shows both sides' steps.
import { useState } from "react";

import { SERVER_ACTIONS } from "../lib/matrix";
import { explain } from "../lib/explanations";
import { serverTap, type Card } from "../lib/browser/playground";
import type { Tapper } from "./Playground";
import { Info, ResultCard, Text } from "./ui";

export default function ServerTab({ tap, busy }: { tap: Tapper; busy: boolean }) {
  const [card, setCard] = useState<Card | null>(null);
  return (
    <div>
      <p className="explain">
        <Text text={explain("tab.server")} />
      </p>
      <p className="explain">
        <Text text={explain("note.decrypt-failures")} />
      </p>
      <div className="buttons stack">
        {SERVER_ACTIONS.map((action) => {
          const code = "code" in action ? action.code : undefined;
          return (
            <span key={action.id} className="choice">
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  void tap(async (log) => {
                    setCard(await serverTap(log, action.id, action.label, code));
                  })
                }
              >
                {action.label}
                {code && ` → ${code}`}
              </button>
              {code && <Info id={action.id} label={action.label} />}
            </span>
          );
        })}
      </div>
      <ResultCard card={card} />
    </div>
  );
}
