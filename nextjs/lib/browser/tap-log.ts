"use client";

// The log of one tap: one button press, one check or one step of the demo walk. Every line is
// `LOG <tap>.<step> <event> …` (PLAYGROUND.md, "Log"), written through `logLines`, so every JWK
// and header passes the publicOnly gate. The server's lines for the same tap come back in its
// answer as `LOG <tap>.s<n> …` and are added here as they are.
import { logLines, type LogValue } from "../shared";
import { errorCode } from "./polyjose";

/** Where log lines go: the page's log and the browser console. */
export type LogSink = (line: string) => void;

/** The time one step took, for the result card. `ms` is from a monotonic clock. */
export interface Timing {
  readonly name: string;
  readonly ms: number;
}

/**
 * A step that failed and has been logged as `error code=<Code>`. It carries the code only: the
 * error's message is never kept, shown or logged.
 */
export class StepFailed extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "StepFailed";
  }
}

/** The code of any error: a logged step's code, a polyjose code, or the error's type name. */
export function codeOf(err: unknown): string {
  return err instanceof StepFailed ? err.code : errorCode(err);
}

export class TapLog {
  #step = 0;
  readonly timings: Timing[] = [];

  constructor(
    readonly tap: number,
    private readonly sink: LogSink,
  ) {}

  /** A browser step. `rest` is a JSON value (through the publicOnly gate) or a token. */
  step(event: string, fields?: Record<string, LogValue>, rest?: LogValue): void {
    this.#step += 1;
    for (const line of logLines(this.tap, String(this.#step), event, fields, rest)) this.sink(line);
  }

  /**
   * Runs `work` and times it (whole milliseconds, `performance.now`). When it fails, logs
   * `error code=<Code> call=<label> ms=<n>` and throws StepFailed with that code.
   */
  async run<T>(label: string, work: () => Promise<T>): Promise<{ value: T; ms: number }> {
    const start = performance.now();
    try {
      const value = await work();
      const ms = Math.round(performance.now() - start);
      this.timings.push({ name: label, ms });
      return { value, ms };
    } catch (err) {
      const ms = Math.round(performance.now() - start);
      const code = codeOf(err);
      this.timings.push({ name: label, ms });
      this.step("error", { code, call: label, ms });
      throw new StepFailed(code);
    }
  }

  /** One polyjose call: runs it and logs `call <function> ms=<n>`. */
  async call<T>(name: string, work: () => Promise<T>): Promise<T> {
    const { value, ms } = await this.run(name, work);
    this.step("call", { ms }, name);
    return value;
  }

  /** The server's lines for this tap, as its answer returned them; its call times go to the card. */
  server(lines: readonly unknown[]): void {
    for (const line of lines) {
      if (typeof line !== "string" || !line.startsWith(`LOG ${this.tap}.s`)) continue;
      this.sink(line);
      const call = line.match(/^LOG \S+ call (\S+) ms=(\d+)$/);
      if (call) this.timings.push({ name: `server ${call[1]}`, ms: Number(call[2]) });
    }
  }
}
