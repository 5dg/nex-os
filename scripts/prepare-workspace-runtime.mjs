#!/usr/bin/env node
// Packaging contract for the pinned framework and this application's empty
// Server Actions surface. Change the actual shipped bytes, never the comparator.
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync, writeFileSync } from "node:fs";
import { basename, isAbsolute, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const NEXT_VERSION = "16.4.3";
const JSON_MANIFEST = ".next/server/server-reference-manifest.json";
const JS_MANIFEST = ".next/server/server-reference-manifest.js";
const JS_PREFIX = "self.__RSC_SERVER_MANIFEST=";
const PRERENDER_MANIFEST = ".next/prerender-manifest.json";
const PREVIEW_PROPS = ".next/server/preview-props.json";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const plainObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

export function prepareWorkspaceRuntime(directory, sourceDirectory) {
  const root = realpathSync(directory);
  const source = realpathSync(sourceDirectory);
  // These framework features are deliberately unavailable in the current
  // synthetic app. A new use must fail packaging until its key contract exists.
  const sourceFiles = {};
  const forbidden = /\b(?:draftMode|setPreviewData|clearPreviewData|previewData|previewMode|revalidate|revalidatePath|revalidateTag|cacheLife|cacheTag|unstable_cache)\b|next\/(?:headers|cache|dist\/)|use cache|x-prerender-revalidate|x-next-revalidated-tags/i;
  function inspectSource(directory) {
    for (const name of readdirSync(directory).sort()) {
      const path = join(directory, name), entry = lstatSync(path);
      if (entry.isSymbolicLink()) throw new Error("Authored application symlinks are unsupported");
      if (entry.isDirectory()) { inspectSource(path); continue; }
      if (!entry.isFile()) throw new Error("Unsupported authored application input");
      if (/\.(?:[cm]?js|jsx|tsx?|json)$/.test(name)) {
        const bytes = readFileSync(path);
        if (forbidden.test(bytes.toString("utf8"))) throw new Error("Preview or on-demand APIs require a reviewed packaging contract");
        sourceFiles[relative(source, path)] = sha256(bytes);
      }
    }
  }
  if (existsSync(join(source, "pages")) || existsSync(join(source, "src"))) {
    throw new Error("Only the reviewed app-router source layout is supported");
  }
  for (const name of ["app", "lib", "components"]) {
    if (name !== "components" || existsSync(join(source, name))) inspectSource(join(source, name));
  }
  for (const name of readdirSync(source)) {
    if (/^(?:middleware|proxy)\./.test(name)) throw new Error("Additional request middleware needs a reviewed preview contract");
    if (/^next\.config\./.test(name)) {
      const bytes = readFileSync(join(source, name));
      if (forbidden.test(bytes.toString("utf8"))) throw new Error("Preview configuration requires a reviewed packaging contract");
      sourceFiles[name] = sha256(bytes);
    }
  }
  const jsonPath = join(root, JSON_MANIFEST);
  const jsPath = join(root, JS_MANIFEST);
  const version = JSON.parse(readFileSync(join(root, "node_modules/next/package.json"), "utf8")).version;
  if (version !== NEXT_VERSION) throw new Error("Pinned Next version required for no-action packaging");
  for (const path of [jsonPath, jsPath]) {
    if (!lstatSync(path).isFile()) throw new Error("Regular action manifests required");
  }
  const originalJSON = readFileSync(jsonPath, "utf8");
  const originalJS = readFileSync(jsPath, "utf8");
  const manifest = JSON.parse(originalJSON);
  if (!plainObject(manifest) || Object.keys(manifest).sort().join(",") !== "edge,encryptionKey,node" ||
      !plainObject(manifest.node) || !plainObject(manifest.edge)) {
    throw new Error("Unsupported action manifest format");
  }
  if (Object.keys(manifest.node).length || Object.keys(manifest.edge).length) {
    throw new Error("Server Actions require a separately reviewed key and reproducibility contract");
  }
  if (typeof manifest.encryptionKey !== "string" || Buffer.from(manifest.encryptionKey, "base64").length !== 32 ||
      Buffer.from(manifest.encryptionKey, "base64").toString("base64") !== manifest.encryptionKey) {
    throw new Error("Unsupported generated action key format");
  }
  if (originalJS !== JS_PREFIX + JSON.stringify(originalJSON)) {
    throw new Error("Action JSON and JavaScript manifests are not exact mirrors");
  }
  const prerenderPath = join(root, PRERENDER_MANIFEST), previewPath = join(root, PREVIEW_PROPS);
  if (!lstatSync(prerenderPath).isFile() || !lstatSync(previewPath).isFile()) throw new Error("Regular preview manifests required");
  const originalPrerender = readFileSync(prerenderPath, "utf8"), originalPreview = readFileSync(previewPath, "utf8");
  const prerender = JSON.parse(originalPrerender), preview = JSON.parse(originalPreview);
  if (!plainObject(prerender) || prerender.version !== 4 ||
      Object.keys(prerender).sort().join(",") !== "dynamicRoutes,notFoundRoutes,preview,routes,version" ||
      !plainObject(preview) || Object.keys(preview).sort().join(",") !== "previewModeEncryptionKey,previewModeId,previewModeSigningKey" ||
      JSON.stringify(prerender.preview) !== JSON.stringify(preview)) throw new Error("Unsupported preview manifest format");
  for (const [name, length] of [["previewModeId", 32], ["previewModeSigningKey", 64], ["previewModeEncryptionKey", 64]]) {
    if (typeof preview[name] !== "string" || !new RegExp("^[a-f0-9]{" + length + "}$").test(preview[name])) {
      throw new Error("Unsupported generated preview credential format");
    }
  }
  const previewKeys = Object.values(preview).map(value => Buffer.from(value));
  const key = Buffer.from(manifest.encryptionKey);
  let checkedFiles = 0;
  let emptyRouteManifests = 0;
  // No executable output, framework dependency, or unexpected manifest can
  // retain the generated key. Reject unfamiliar variants instead of stripping.
  function inspect(directory) {
    for (const name of readdirSync(directory).sort()) {
      const path = join(directory, name);
      const entry = lstatSync(path);
      const pathName = relative(root, path).split("\\").join("/");
      if (entry.isSymbolicLink()) {
        const target = relative(root, realpathSync(path));
        if (target === ".." || target.startsWith("../") || isAbsolute(target)) {
          throw new Error("Runtime symlink escapes the inspected package");
        }
        continue; // In-tree targets are inspected at their regular pathname.
      }
      if (entry.isDirectory()) { inspect(path); continue; }
      if (!entry.isFile()) throw new Error("Unsupported runtime file type");
      checkedFiles++;
      const expected = pathName === JSON_MANIFEST || pathName === JS_MANIFEST;
      if (basename(path).startsWith("server-reference-manifest") && !expected) {
        if (!/^\.next\/server\/app\/(?:.+\/)?(?:page|route)\/server-reference-manifest\.json$/.test(pathName)) {
          throw new Error("Unexpected action manifest variant");
        }
        const partial = JSON.parse(readFileSync(path, "utf8"));
        if (!plainObject(partial) || Object.keys(partial).sort().join(",") !== "edge,node" ||
            !plainObject(partial.node) || !plainObject(partial.edge) ||
            Object.keys(partial.node).length || Object.keys(partial.edge).length) {
          throw new Error("Route action manifest must have exactly empty node and edge maps");
        }
        emptyRouteManifests++;
      }
      if (!expected && readFileSync(path).includes(key)) {
        throw new Error("Generated action key occurs outside the admitted manifests");
      }
      if (pathName !== PRERENDER_MANIFEST && pathName !== PREVIEW_PROPS) {
        const bytes = readFileSync(path);
        if (previewKeys.some(value => bytes.includes(value))) throw new Error("Generated preview credentials occur outside admitted manifests");
        if (basename(path).startsWith("preview-props")) throw new Error("Unexpected preview manifest variant");
      }
    }
  }
  inspect(root);
  const preparedJSON = JSON.stringify({ node: {}, edge: {} }, null, 2);
  const preparedJS = JS_PREFIX + JSON.stringify(preparedJSON);
  // false cannot equal a Node header (undefined/string) or Web Headers value
  // (null/string). Omitting the ID or using null would incorrectly authenticate
  // an absent revalidation header in one of those code paths.
  const disabledPreview = { previewModeId: false };
  prerender.preview = disabledPreview;
  const preparedPrerender = JSON.stringify(prerender, null, 2);
  const preparedPreview = JSON.stringify(disabledPreview, null, 2);
  writeFileSync(jsonPath, preparedJSON);
  writeFileSync(jsPath, preparedJS);
  writeFileSync(prerenderPath, preparedPrerender);
  writeFileSync(previewPath, preparedPreview);
  return {
    schema_version: 1, contract: "next-16.4.3-no-actions-disabled-preview-v1", next_version: version,
    action_counts: { node: 0, edge: 0 }, inspected_regular_files: checkedFiles,
    empty_route_manifests: emptyRouteManifests,
    operation: "remove unused action key and disable unused preview/revalidation with a non-string false marker",
    preview_enabled: false, authored_source_checks: sourceFiles,
    generated_key_material_retained: false, comparison_exclusions: [],
    files: {
      [JSON_MANIFEST]: { before_sha256: sha256(originalJSON), after_sha256: sha256(preparedJSON) },
      [JS_MANIFEST]: { before_sha256: sha256(originalJS), after_sha256: sha256(preparedJS) },
      [PRERENDER_MANIFEST]: { before_sha256: sha256(originalPrerender), after_sha256: sha256(preparedPrerender) },
      [PREVIEW_PROPS]: { before_sha256: sha256(originalPreview), after_sha256: sha256(preparedPreview) },
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 5) throw new Error("Usage: prepare-workspace-runtime.mjs standalone-directory authored-source-directory report.json");
    const report = prepareWorkspaceRuntime(process.argv[2], process.argv[3]);
    writeFileSync(process.argv[4], JSON.stringify(report, null, 2) + "\n", { flag: "wx", mode: 0o600 });
    process.stdout.write("Pinned no-action/disabled-preview packaging verified; no generated key material retained.\n");
  } catch {
    // Framework-generated key bytes and arbitrary input must never enter logs.
    process.stderr.write("Workspace runtime preparation rejected; inspect the pinned no-action packaging contract.\n");
    process.exitCode = 1;
  }
}
