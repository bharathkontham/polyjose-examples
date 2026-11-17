// `npm start`: serves the example on PORT (default 3000). Configuration: config.ts, README.md.
import process from "node:process";

import { createApp } from "./app.js";
import { configFromEnv } from "./config.js";

// A whole number from 0 to 65535; anything else stops the boot instead of reaching listen() as NaN.
const portText = process.env.PORT ?? "3000";
const port = /^\d{1,5}$/.test(portText) ? Number(portText) : Number.NaN;
if (!(port >= 0 && port <= 65535)) {
  console.error("PORT must be a whole number from 0 to 65535");
  process.exit(2);
}

const app = await createApp(configFromEnv(process.env));
app.enableShutdownHooks();
await app.listen(port);
