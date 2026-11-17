// A global module: any controller or guard can inject KeyService and TokenService.
import { type DynamicModule, Module } from "@nestjs/common";

import { POLYJOSE_CONFIG, type PolyjoseConfig } from "../config.js";
import { KeyService } from "./key.service.js";
import { TokenService } from "./token.service.js";

@Module({})
export class PolyjoseModule {
  static forRoot(config: PolyjoseConfig): DynamicModule {
    return {
      module: PolyjoseModule,
      global: true,
      providers: [{ provide: POLYJOSE_CONFIG, useValue: config }, KeyService, TokenService],
      exports: [KeyService, TokenService],
    };
  }
}
