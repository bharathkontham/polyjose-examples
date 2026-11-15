// A static file server for this folder, on 127.0.0.1 only, with no dependencies (Node `http`).
// The page needs one because a browser does not fetch WebAssembly from a file:// URL, and the
// .wasm must be served as `application/wasm` to compile.
//
//   node serve.mjs              then open the printed URL (default port 8000)
//   node serve.mjs --port 0     any free port; the URL line says which
//
// It prints `serving http://127.0.0.1:<port>/` once it listens. It serves GET and HEAD for the
// files under this folder (node_modules included, for the package) and nothing else.
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".wasm": "application/wasm",
  ".css": "text/css; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".md": "text/plain; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

function parsePort(argv) {
  const i = argv.indexOf("--port");
  const value = i >= 0 ? argv[i + 1] : (process.env.PORT ?? "8000");
  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    console.error(`serve.mjs: not a port: ${value}`);
    process.exit(2);
  }
  return port;
}

/** The file a URL path names, or null when it would leave this folder. */
function fileFor(urlPath) {
  let decoded;
  try {
    decoded = decodeURIComponent(urlPath);
  } catch {
    return null;
  }
  if (decoded.includes("\0")) return null;
  const file = path.resolve(root, `.${decoded.endsWith("/") ? `${decoded}index.html` : decoded}`);
  return file === root || file.startsWith(root + path.sep) ? file : null;
}

function send(res, status, text) {
  res.writeHead(status, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
  res.end(`${text}\n`);
}

const server = http.createServer(async (req, res) => {
  if (req.method !== "GET" && req.method !== "HEAD") return send(res, 405, "method not allowed");
  const file = fileFor(new URL(req.url, "http://localhost").pathname);
  if (file === null) return send(res, 403, "forbidden");
  let info;
  try {
    info = await stat(file);
  } catch {
    return send(res, 404, "not found");
  }
  if (!info.isFile()) return send(res, 404, "not found");
  res.writeHead(200, {
    "content-type": TYPES[path.extname(file)] ?? "application/octet-stream",
    "content-length": info.size,
    "cache-control": "no-store", // a rebuilt package is picked up on reload
    "x-content-type-options": "nosniff",
  });
  if (req.method === "HEAD") return res.end();
  createReadStream(file).on("error", () => res.destroy()).pipe(res);
});

server.listen(parsePort(process.argv.slice(2)), "127.0.0.1", () => {
  console.log(`serving http://127.0.0.1:${server.address().port}/`);
});
