// The last line of the secrets rule: an error that is not an HttpException becomes a plain 500,
// and only its name is logged. Nest's default handler would log its message and stack, and a
// library message is not ours to log.
import { type ArgumentsHost, Catch, type ExceptionFilter, HttpException, Logger } from "@nestjs/common";
import { HttpAdapterHost } from "@nestjs/core";
import { PolyjoseError } from "@polyjose/node";

@Catch()
export class SafeExceptionFilter implements ExceptionFilter {
  readonly #logger = new Logger("Exceptions");

  constructor(private readonly adapterHost: HttpAdapterHost) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const { httpAdapter } = this.adapterHost;
    const response: unknown = host.switchToHttp().getResponse();
    if (exception instanceof HttpException) {
      const body = exception.getResponse();
      const status = exception.getStatus();
      httpAdapter.reply(response, typeof body === "object" ? body : { statusCode: status, message: body }, status);
      return;
    }
    const what = exception instanceof PolyjoseError ? `code=${exception.code}` : `name=${exception instanceof Error ? exception.name : typeof exception}`;
    this.#logger.error(`unhandled error ${what}`);
    httpAdapter.reply(response, { statusCode: 500, message: "Internal Server Error" }, 500);
  }
}
