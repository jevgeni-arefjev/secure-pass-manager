// Builds the client into ../vault-web/assets, which vault-web's build.rs embeds:
// the esbuild bundle (app.js) plus the static files (index.html, app.css).
// Stale files from an earlier build are removed first; .gitkeep stays.

import { copyFile, mkdir, readdir, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

import { build } from "esbuild";

const web = fileURLToPath(new URL("..", import.meta.url));
const assets = join(web, "..", "vault-web", "assets");
const staticDir = join(web, "static");

await mkdir(assets, { recursive: true });
for (const name of await readdir(assets)) {
  if (name !== ".gitkeep") {
    await rm(join(assets, name), { recursive: true, force: true });
  }
}

await build({
  entryPoints: [join(web, "src", "main.ts")],
  outfile: join(assets, "app.js"),
  bundle: true,
  format: "esm",
  target: "es2022",
  minify: true,
  legalComments: "none",
  logLevel: "info",
});

for (const name of await readdir(staticDir)) {
  await copyFile(join(staticDir, name), join(assets, name));
}
console.log(`client built into ${assets}`);
