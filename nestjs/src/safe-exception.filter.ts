// The last line of the secrets rule. Only a body the app built itself reaches the client; any
// other error is answered with its status and a fixed reason phrase. Nest's own exceptions can
// quote the request: its 404 says `Cannot GET /token?client_secret=...`, and the body parser's
// 413 and 415 carry their own texts. An error that is not an HttpException becomes a plain 500,
// and only its name or polyjose code is logged: Nest's default handler would log its message and
// stack, and a library message is not ours to log.
import { STATUS_CODES } from "node:http";

import { type ArgumentsHost, Catch, type ExceptionFilter, HttpException, Logger } from "@nestjs/common";
import { HttpAdapterHost } from "@nestjs/core";
import { PolyjoseError } from "@polyjose/node";

/**
 * An error response whose body the app wrote and that is safe to send as it is: the RFC 6749
 * §5.2 `{ error }` bodies of `POST /token` and the RFC 6750 §3.1 bodies of the guard.
 */
export class AppHttpException extends HttpException {
  constructor(body: Readonly<Record<string, string>>, status: number) {
    super(body, status);
  }
}

/** `{ statusCode, message }` with the standard reason phrase (RFC 9110 §15) and nothing else. */
function fixedBody(status: number): { statusCode: number; message: string } {
  return { statusCode: status, message: STATUS_CODES[status] ?? "Error" };
}

@Catch()
export class SafeExceptionFilter implements ExceptionFilter {
  readonly #logger = new Logger("Exceptions");

  constructor(private readonly adapterHost: HttpAdapterHost) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const { httpAdapter } = this.adapterHost;
    const response: unknown = host.switchToHttp().getResponse();
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const body = exception instanceof AppHttpException ? exception.getResponse() : fixedBody(status);
      httpAdapter.reply(response, body, status);
      return;
    }
    const what = exception instanceof PolyjoseError ? `code=${exception.code}` : `name=${exception instanceof Error ? exception.name : typeof exception}`;
    this.#logger.error(`unhandled error ${what}`);
    httpAdapter.reply(response, fixedBody(500), 500);
  }
}
