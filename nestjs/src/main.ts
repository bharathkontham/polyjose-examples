// `npm start`: serves the example on PORT (default 3000). Configuration: config.ts, README.md.
import process from "node:process";

import { createApp } from "./app.js";
import { configFromEnv } from "./config.js";

const app = await createApp(configFromEnv(process.env));
app.enableShutdownHooks();
await app.listen(Number(process.env.PORT ?? 3000));
