"""Actual emitted runtime bytes and fail-closed no-action packaging; no Docker."""
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/prepare-workspace-runtime.mjs'
PREFIX = 'self.__RSC_SERVER_MANIFEST='


class WorkspacePackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fixture(self, name='runtime', key=b'a'*32, **changes):
        root = self.root / name
        (root / '.next/server').mkdir(parents=True)
        (root / 'node_modules/next').mkdir(parents=True)
        (root / 'node_modules/next/package.json').write_text('{"version":"16.4.3"}')
        (root / 'authored/app').mkdir(parents=True)
        (root / 'authored/lib').mkdir()
        (root / 'authored/app/page.tsx').write_text('export default function Page(){return null;}')
        manifest = {'node': {}, 'edge': {}, 'encryptionKey': base64.b64encode(key).decode()}
        manifest.update(changes)
        text = json.dumps(manifest, indent=2)
        (root / '.next/server/server-reference-manifest.json').write_text(text)
        (root / '.next/server/server-reference-manifest.js').write_text(PREFIX + json.dumps(text, separators=(',', ':')))
        (root / 'server.js').write_text('// unchanged executable fixture\n')
        preview = {'previewModeId': key.hex()[:32], 'previewModeSigningKey': key.hex(), 'previewModeEncryptionKey': bytes(reversed(key)).hex()}
        (root / '.next/prerender-manifest.json').write_text(json.dumps({'version': 4, 'routes': {}, 'dynamicRoutes': {}, 'notFoundRoutes': [], 'preview': preview}))
        (root / '.next/server/preview-props.json').write_text(json.dumps(preview))
        return root, manifest

    def run_preparation(self, root):
        return subprocess.run(['node', str(SCRIPT), str(root), str(root / 'authored'), str(root.parent / (root.name + '-report.json'))], capture_output=True, text=True)

    def manifests(self, root):
        return [(root / path).read_bytes() for path in ('.next/server/server-reference-manifest.json', '.next/server/server-reference-manifest.js', '.next/prerender-manifest.json', '.next/server/preview-props.json')]

    def assert_rejected_unchanged(self, root):
        before = self.manifests(root)
        self.assertNotEqual(self.run_preparation(root).returncode, 0)
        self.assertEqual(before, self.manifests(root))

    def test_independent_random_keys_produce_same_actual_shipped_bytes(self):
        one, _ = self.fixture('one', b'a'*32)
        two, _ = self.fixture('two', b'b'*32)
        self.assertNotEqual(self.manifests(one), self.manifests(two))
        for root in (one, two):
            original_executable = (root / 'server.js').read_bytes()
            result = self.run_preparation(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / 'server.js').read_bytes(), original_executable)
            self.assertEqual(json.loads(self.manifests(root)[0]), {'node': {}, 'edge': {}})
            report = json.loads((root.parent / (root.name + '-report.json')).read_text())
            self.assertEqual(report['comparison_exclusions'], [])
            self.assertFalse(report['generated_key_material_retained'])
            self.assertEqual(json.loads(self.manifests(root)[2])['preview'], {'previewModeId': False})
            self.assertEqual(json.loads(self.manifests(root)[3]), {'previewModeId': False})
        self.assertEqual(self.manifests(one), self.manifests(two))

    def test_node_and_edge_actions_reject_before_mutation(self):
        for kind in ('node', 'edge'):
            root, _ = self.fixture(kind, **{kind: {'action': {'workers': {}}}})
            self.assert_rejected_unchanged(root)

    def test_unknown_manifest_fields_and_invalid_keys_reject(self):
        for name, changes in [('extra', {'future': {}}), ('invalid', {'encryptionKey': 'not-a-key'}), ('maps', {'node': []})]:
            root, _ = self.fixture(name, **changes)
            self.assert_rejected_unchanged(root)

    def test_unexpected_manifest_variants_or_key_occurrences_reject(self):
        for name, path in [('variant', '.next/server/server-reference-manifest.extra.json'), ('leak', '.next/server/chunk.js')]:
            root, manifest = self.fixture(name)
            (root / path).write_text(manifest['encryptionKey'])
            self.assert_rejected_unchanged(root)

    def test_framework_version_and_mirror_substitution_reject(self):
        root, _ = self.fixture('version')
        (root / 'node_modules/next/package.json').write_text('{"version":"16.4.4"}')
        self.assert_rejected_unchanged(root)
        root, _ = self.fixture('mirror')
        (root / '.next/server/server-reference-manifest.js').write_text(PREFIX + '"different"')
        self.assert_rejected_unchanged(root)

    def test_partial_route_manifests_prove_empty_and_reject_extra_key_or_action(self):
        for name, partial in [('empty', {'node': {}, 'edge': {}}),
                              ('key', {'node': {}, 'edge': {}, 'encryptionKey': 'new'}),
                              ('action', {'node': {'action': {}}, 'edge': {}})]:
            root, _ = self.fixture(name)
            path = root / '.next/server/app/workflow/page/server-reference-manifest.json'
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(partial))
            if name == 'empty':
                before = path.read_bytes()
                self.assertEqual(self.run_preparation(root).returncode, 0)
                self.assertEqual(path.read_bytes(), before)
            else:
                self.assert_rejected_unchanged(root)

    def test_preview_api_use_and_new_source_layout_reject(self):
        for name, source in [('draft', 'import {draftMode as d} from "next/headers";'), ('preview', 'response.setPreviewData({});'), ('revalidation', 'revalidateTag("tag");')]:
            root, _ = self.fixture(name)
            (root / 'authored/app/page.tsx').write_text(source)
            self.assert_rejected_unchanged(root)
        root, _ = self.fixture('pages')
        (root / 'authored/pages').mkdir()
        self.assert_rejected_unchanged(root)

    def test_preview_key_leaks_or_unknown_fields_reject(self):
        root, _ = self.fixture('preview-leak')
        preview = json.loads((root / '.next/server/preview-props.json').read_text())
        (root / 'server.js').write_text(preview['previewModeSigningKey'])
        self.assert_rejected_unchanged(root)
        root, _ = self.fixture('preview-extra')
        path = root / '.next/server/preview-props.json'
        preview = json.loads(path.read_text()); preview['future'] = True; path.write_text(json.dumps(preview))
        self.assert_rejected_unchanged(root)

    def test_pinned_framework_false_marker_denies_node_and_web_header_authority(self):
        # Exercise the real frozen dependency, not a mock of its equality rules.
        # `undefined` and `null` would accept one absent-header representation.
        program = r'''
import {createRequire} from 'node:module';
import assert from 'node:assert/strict';
const require=createRequire(process.cwd()+'/apps/workspace/package.json');
assert.equal(require('next/package.json').version,'16.4.3');
const {checkIsOnDemandRevalidate}=require('next/dist/server/api-utils/index.js');
const {DraftModeProvider}=require('next/dist/server/async-storage/draft-mode-provider.js');
const {tryGetPreviewData}=require('next/dist/server/api-utils/node/try-get-preview-data.js');
process.env.NODE_ENV='production';
const preview={previewModeId:false};
for(const value of [undefined,'','false','null','undefined','0'.repeat(32)]){
 const headers=value===undefined?{}:{'x-prerender-revalidate':value};
 for(const representation of [headers,new Headers(headers)]){
  assert.equal(checkIsOnDemandRevalidate(representation,preview).isOnDemandRevalidate,false);
  const draft=new DraftModeProvider(preview,representation,{get:()=>value===undefined?undefined:{value}},{set:()=>{throw new Error('unexpected cookie write')}});
  assert.equal(draft.isEnabled,false);
  assert.throws(()=>draft.enable(),/missing previewModeId/);
 }
 const cookies=value===undefined?{}:{cookie:'__prerender_bypass='+value+'; __next_preview_data=invalid'};
 const recorded=new Map();
 assert.equal(tryGetPreviewData({headers:cookies},{getHeader:n=>recorded.get(n),setHeader:(n,v)=>recorded.set(n,v)},preview,false),false);
}
'''
        result = subprocess.run(['node', '--input-type=module', '-'], input=program,
                                cwd=SCRIPT.parent.parent, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_external_symlink_rejects_before_mutation(self):
        root, _ = self.fixture('symlink')
        (self.root / 'outside.txt').write_text('outside')
        (root / 'outside').symlink_to(self.root / 'outside.txt')
        self.assert_rejected_unchanged(root)


if __name__ == '__main__':
    unittest.main()
