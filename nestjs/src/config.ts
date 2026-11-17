// The service's configuration, read once from environment variables (see README.md).
//
//   POLYJOSE_SIGNING_JWKS       a private JWK Set (RFC 7517 §5) as JSON text; the first key signs
//   POLYJOSE_SIGNING_JWKS_FILE  a path to a file holding that JWK Set (used when the above is unset)
//   POLYJOSE_ISSUER             the `iss` of issued tokens (default http://localhost:3000)
//   POLYJOSE_AUDIENCE           the `aud` of issued tokens (default polyjose-examples-nestjs)
//   POLYJOSE_DEMO_CLIENT_ID     the one client `POST /token` serves (default demo-client)
//   POLYJOSE_DEMO_CLIENT_SECRET its secret; when unset, `POST /token` refuses every request
//   PORT                        the HTTP port (default 3000)

/** Where the signing keys come from. This object can hold private keys: never log it. */
export interface SigningKeySource {
  /** The JWK Set's JSON text, from `POLYJOSE_SIGNING_JWKS`. */
  readonly json?: string | undefined;
  /** A file path, from `POLYJOSE_SIGNING_JWKS_FILE`. */
  readonly file?: string | undefined;
}

export interface PolyjoseConfig {
  readonly signingKeys: SigningKeySource;
  /** `iss` (RFC 7519 §4.1.1): set on issue, required on verify (RFC 8725 §3.8). */
  readonly issuer: string;
  /** `aud` (RFC 7519 §4.1.3): set on issue, required on verify (RFC 8725 §3.9). */
  readonly audience: string;
  /** Token lifetime in seconds: `exp` = `iat` + this (RFC 7519 §4.1.4, §4.1.6). */
  readonly tokenTtlSeconds: number;
  /** Clock skew allowed on `exp` and `nbf`, in seconds (RFC 7519 §4.1.4). */
  readonly leewaySeconds: number;
}

/** The one demo client of `POST /token`. The secret is never logged or returned. */
export interface DemoClientConfig {
  readonly clientId: string;
  readonly clientSecret?: string | undefined;
}

export interface AppConfig {
  readonly polyjose: PolyjoseConfig;
  readonly client: DemoClientConfig;
}

/** The injection tokens of the two config objects. */
export const POLYJOSE_CONFIG = Symbol("POLYJOSE_CONFIG");
export const DEMO_CLIENT_CONFIG = Symbol("DEMO_CLIENT_CONFIG");

const nonEmpty = (value: string | undefined): string | undefined => (value === undefined || value === "" ? undefined : value);

/** Builds the configuration from `env` (normally `process.env`). */
export function configFromEnv(env: Readonly<Record<string, string | undefined>>): AppConfig {
  return {
    polyjose: {
      signingKeys: { json: nonEmpty(env.POLYJOSE_SIGNING_JWKS), file: nonEmpty(env.POLYJOSE_SIGNING_JWKS_FILE) },
      issuer: nonEmpty(env.POLYJOSE_ISSUER) ?? "http://localhost:3000",
      audience: nonEmpty(env.POLYJOSE_AUDIENCE) ?? "polyjose-examples-nestjs",
      tokenTtlSeconds: 300,
      leewaySeconds: 30,
    },
    client: {
      clientId: nonEmpty(env.POLYJOSE_DEMO_CLIENT_ID) ?? "demo-client",
      clientSecret: nonEmpty(env.POLYJOSE_DEMO_CLIENT_SECRET),
    },
  };
}
