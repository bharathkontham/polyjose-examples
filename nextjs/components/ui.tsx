"use client";

// The small pieces every tab uses: explanation text, the info button, the copy button and the
// result card. Every JWK or header shown here passes the one publicOnly gate first.
import { Fragment, useState, type ReactNode } from "react";

import { explain, explainCode } from "../lib/explanations";
import { publicOnly } from "../lib/shared";
import { asExpected, type Card } from "../lib/browser/playground";

/** An explanation text, with its `code` spans. */
export function Text({ text }: { text: string }) {
  return (
    <>
      {text.split("`").map((part, i) => (i % 2 === 1 ? <code key={i}>{part}</code> : <Fragment key={i}>{part}</Fragment>))}
    </>
  );
}

/** The info button of a row: shows the explanation of `id` below it. */
export function Info({ id, label }: { id: string; label: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" className="info" aria-expanded={open} aria-label={`About ${label}`} onClick={() => setOpen(!open)}>
        i
      </button>
      {open && (
        <span className="explain" role="note">
          <Text text={explain(id)} />
        </span>
      )}
    </>
  );
}

/** JSON as the page shows it: through the publicOnly gate, indented. */
export function Json({ value }: { value: unknown }) {
  return <pre className="mono">{JSON.stringify(publicOnly(value), null, 2)}</pre>;
}

/** Copies `text` to the clipboard (`navigator.clipboard`); a failure shows its error name only. */
export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [state, setState] = useState("");
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setState("copied");
    } catch (err) {
      setState(`not copied (${err instanceof Error ? err.name : "error"})`);
    }
  };
  return (
    <button type="button" onClick={() => void copy()}>
      {label}
      {state && ` · ${state}`}
    </button>
  );
}

/** One row of radio buttons; a disabled option shows its reason. */
export function Choice<T extends string>({
  name,
  legend,
  options,
  value,
  onChange,
  info,
}: {
  name: string;
  legend: string;
  options: readonly { value: T; label: string; disabled?: string | undefined }[];
  value: T;
  onChange: (value: T) => void;
  info?: (value: T) => string | undefined;
}) {
  return (
    <fieldset>
      <legend>{legend}</legend>
      <div className="choices">
        {options.map((option) => {
          const infoId = info?.(option.value);
          return (
            <span key={option.value} className={option.disabled ? "choice disabled" : "choice"}>
              <label>
                <input
                  type="radio"
                  name={name}
                  value={option.value}
                  checked={value === option.value}
                  disabled={option.disabled !== undefined}
                  onChange={() => onChange(option.value)}
                />
                {option.label}
                {option.disabled && <span className="reason"> — {explain(option.disabled)}</span>}
              </label>
              {infoId && <Info id={infoId} label={option.label} />}
            </span>
          );
        })}
      </div>
    </fieldset>
  );
}

/** A labelled section of the result card. */
function Part({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="part">
      <h4>{title}</h4>
      {children}
    </div>
  );
}

/**
 * The result card (PLAYGROUND.md, "The result card"): the token and its protected header, the
 * outcome or the error code and its explanation, where the key lives and each step's time.
 */
export function ResultCard({ card }: { card: Card | null }) {
  if (!card) return null;
  const matched = asExpected(card);
  return (
    <section className={`card ${matched ? "good" : "bad"}`} aria-live="polite" data-outcome={matched ? "expected" : "unexpected"}>
      <h3>{card.title}</h3>
      {card.token !== undefined && (
        <Part title="Token">
          <pre className="mono token">{card.token}</pre>
          <CopyButton text={card.token} label="Copy token" />
        </Part>
      )}
      {card.header !== undefined && (
        <Part title="Protected header">
          <Json value={card.header} />
        </Part>
      )}
      <Part title="Outcome">
        {card.outcome.ok ? (
          card.outcome.lines.map((line) => <p key={line}>{line}</p>)
        ) : (
          <>
            <p>
              Refused by the {card.outcome.side}: <code>{card.outcome.code}</code>
            </p>
            <p className="explain">
              <Text text={explainCode(card.outcome.code)} />
            </p>
          </>
        )}
        {card.expected !== undefined && (
          <p>
            Expected <code>{card.expected}</code>: {matched ? "yes" : "no"}.
          </p>
        )}
      </Part>
      {card.notes.map((id) => (
        <p key={id} className="explain">
          <Text text={explain(id)} />
        </p>
      ))}
      <p>Key lives in: {card.keyLives}</p>
      <Part title="Steps">
        <ul className="timings">
          {card.timings.map((timing, i) => (
            <li key={i}>
              {timing.name}: {timing.ms} ms
            </li>
          ))}
        </ul>
      </Part>
    </section>
  );
}
