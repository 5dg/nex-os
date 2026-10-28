// Verify the bytes about to be compiled against the captured immutable inputs.
// Only npm's exact root node_modules directory may be added after installation.
// Next outputs (.next, next-env.d.ts, etc.) are not exceptions before compilation.
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, posix } from 'node:path';
import { pathToFileURL } from 'node:url';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const sorted = value => Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
const canonicalJSON = value => JSON.stringify(value).replace(/[\u007f-\uffff]/g, char => '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0'));

export function verifyStaging(source, staged, phase, inputHash) {
  if (!['pristine', 'installed'].includes(phase)) throw new Error('unknown staging phase');
  const companion = join(source, '.nex-source.json');
  if (!lstatSync(companion).isFile() || lstatSync(companion).isSymbolicLink()) throw new Error('non-regular source companion');
  const record = JSON.parse(readFileSync(companion, 'utf8'));
  const { files, modes, sha256 } = record.inputs;
  if (record.schema_version !== 1 || !/^[a-f0-9]{64}$/.test(inputHash) || sha256 !== inputHash ||
      hash(canonicalJSON({ files: sorted(files), modes: sorted(modes) })) !== inputHash) {
    throw new Error('captured input identity mismatch');
  }
  const prefix = 'apps/workspace/';
  const expected = Object.create(null);
  const directories = new Set(['']);
  for (const name of Object.keys(files).sort()) {
    if (!name.startsWith(prefix)) continue;
    const relative = name.slice(prefix.length);
    if (!relative || relative.split('/').some(part => !part || part === '.' || part === '..') ||
        ['node_modules', '.next'].includes(relative.split('/')[0]) ||
        !/^[a-f0-9]{64}$/.test(files[name]) || !Number.isInteger(modes[name]) || modes[name] < 0 || modes[name] > 0o7777) {
      throw new Error('invalid authored input: ' + name);
    }
    expected[relative] = { sha256: files[name], mode: modes[name] };
    for (let dir = posix.dirname(relative); dir !== '.'; dir = posix.dirname(dir)) directories.add(dir);
  }
  if (!expected['package.json'] || !expected['package-lock.json']) throw new Error('missing workspace manifests');
  function inspect(root, allowDependencies) {
    const observed = Object.create(null);
    function visit(relative) {
      const path = join(root, relative);
      const stat = lstatSync(path);
      if (stat.isSymbolicLink()) throw new Error('authored symlink: ' + relative);
      if (relative === 'node_modules' && allowDependencies && stat.isDirectory()) return;
      if (stat.isDirectory()) {
        if (!directories.has(relative)) throw new Error('unexpected authored directory: ' + relative);
        for (const name of readdirSync(path).sort()) visit(relative ? relative + '/' + name : name);
      } else {
        if (!stat.isFile() || !Object.hasOwn(expected, relative)) throw new Error('unexpected or non-regular authored file: ' + relative);
        const actual = { sha256: hash(readFileSync(path)), mode: stat.mode & 0o7777 };
        if (actual.sha256 !== expected[relative].sha256 || actual.mode !== expected[relative].mode) throw new Error('authored content/mode mismatch: ' + relative);
        observed[relative] = actual;
      }
    }
    visit('');
    if (Object.keys(observed).length !== Object.keys(expected).length) throw new Error('missing authored file');
  }
  inspect(join(source, 'apps/workspace'), false);
  inspect(staged, phase === 'installed');
  return { schema_version: 1, phase, source_input_sha256: inputHash,
    source_companion_sha256: hash(readFileSync(companion)),
    allowed_generated_roots: phase === 'installed' ? ['node_modules'] : [], files: expected };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 6) throw new Error('Usage: verify-workspace-staging.mjs source staged pristine|installed report.json');
    const report = verifyStaging(process.argv[2], process.argv[3], process.argv[4], process.env.NEX_SOURCE_INPUT_SHA256);
    writeFileSync(process.argv[5], JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
