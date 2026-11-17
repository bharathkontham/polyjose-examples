import { type DynamicModule, Module } from "@nestjs/common";
import { APP_FILTER } from "@nestjs/core";

import { type AppConfig, DEMO_CLIENT_CONFIG } from "./config.js";
import { PolyjoseModule } from "./polyjose/polyjose.module.js";
import { JwksController } from "./routes/jwks.controller.js";
import { MeController } from "./routes/me.controller.js";
import { TokenController } from "./routes/token.controller.js";
import { SafeExceptionFilter } from "./safe-exception.filter.js";

@Module({})
export class AppModule {
  static forRoot(config: AppConfig): DynamicModule {
    return {
      module: AppModule,
      imports: [PolyjoseModule.forRoot(config.polyjose)],
      controllers: [JwksController, TokenController, MeController],
      providers: [
        { provide: DEMO_CLIENT_CONFIG, useValue: config.client },
        { provide: APP_FILTER, useClass: SafeExceptionFilter },
      ],
    };
  }
}
