// Builds the Nest application; main.ts serves it, verify.ts runs the checks against it.
import { type LoggerService } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import type { NestExpressApplication } from "@nestjs/platform-express";

import { AppModule } from "./app.module.js";
import type { AppConfig } from "./config.js";

export async function createApp(config: AppConfig, logger?: LoggerService): Promise<NestExpressApplication> {
  // Only the form parser that POST /token needs (RFC 6749 §4.4.2); no JSON body parser.
  const app = await NestFactory.create<NestExpressApplication>(AppModule.forRoot(config), {
    bodyParser: false,
    ...(logger === undefined ? {} : { logger }),
  });
  app.useBodyParser("urlencoded", { extended: false });
  app.disable("x-powered-by");
  return app;
}
