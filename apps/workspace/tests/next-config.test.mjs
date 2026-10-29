import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const workspace = fileURLToPath(new URL('..', import.meta.url));

test('pinned Next resolves identical serialized config across host CPU counts', () => {
  const results = [5, 17].map((hostCpus) => {
    // A fresh process is essential: Next caches both its defaults and loaded config.
    const child = spawnSync(process.execPath, ['--input-type=commonjs', '-e', `
      const assert = require('node:assert/strict');
      const os = require('node:os');
      os.cpus = () => Array.from({ length: ${hostCpus} }, () => ({ model: 'fixture', speed: 1, times: {} }));
      delete process.env.CIRCLE_NODE_TOTAL;
      delete process.env.__NEXT_PRIVATE_STANDALONE_CONFIG;
      assert.equal(require('next/package.json').version, '16.4.3');
      const { defaultConfig } = require('next/dist/server/config-shared');
      const loadConfig = require('next/dist/server/config').default;
      const { PHASE_PRODUCTION_BUILD } = require('next/constants');
      (async () => {
        const config = await loadConfig(PHASE_PRODUCTION_BUILD, process.cwd());
        assert.equal(config.output, 'standalone');
        assert.equal(config.poweredByHeader, false);
        assert.deepEqual(await config.headers(), [{ source: '/:path*', headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
          { key: 'X-Frame-Options', value: 'DENY' },
        ] }]);
        assert.equal(await config.generateBuildId(), 'a'.repeat(64));
        process.env.NEX_SOURCE_INPUT_SHA256 = 'invalid';
        await assert.rejects(config.generateBuildId(), /Invalid build source input identity/);
        delete process.env.NEX_SOURCE_INPUT_SHA256;
        assert.equal(await config.generateBuildId(), null);
        process.stdout.write(JSON.stringify({ hostDefault: defaultConfig.experimental.cpus,
          config: JSON.parse(JSON.stringify(config)) }));
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `], { cwd: workspace, env: { ...process.env, NEX_SOURCE_INPUT_SHA256: 'a'.repeat(64),
      NEXT_TELEMETRY_DISABLED: '1' }, encoding: 'utf8', timeout: 30_000 });
    assert.ifError(child.error);
    assert.equal(child.status, 0, child.stderr);
    assert.ok(child.stdout, JSON.stringify({cwd:workspace,status:child.status,stderr:child.stderr,error:String(child.error)}));
    return JSON.parse(child.stdout);
  });
  assert.deepEqual(results.map((result) => result.hostDefault), [4, 16],
    'the test must exercise Next host-dependent defaults before the explicit override');
  for (const result of results) assert.equal(result.config.experimental.cpus, 2);
  // Compare the complete serialized resource input, with no omitted fields.
  assert.deepEqual(results[0].config, results[1].config);
});
