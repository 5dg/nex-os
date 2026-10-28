#!/usr/bin/env python3
"""Exercise full Go 1.27 symbol analysis with a synthetic local advisory.

This is scanner compatibility evidence, never project vulnerability clearance.
The fixture is analyzed, not executed; it performs no network requests.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def messages(text):
    decoder = json.JSONDecoder()
    while text.strip():
        item, end = decoder.raw_decode(text.lstrip())
        yield item
        text = text.lstrip()[end:]


def check(binary, output):
    output.mkdir(parents=True, exist_ok=False)
    environment = {**os.environ, 'GOPROXY': 'off', 'GOSUMDB': 'off', 'GOWORK': 'off',
                   'GOTOOLCHAIN': 'local', 'GOFLAGS': '-mod=readonly', 'GOMAXPROCS': '2'}
    toolchain = subprocess.run(['go', 'version'], env=environment, capture_output=True, text=True, check=True).stdout.strip()
    if 'go1.27.3 ' not in toolchain:
        raise ValueError('Compatibility fixture requires the project Go 1.27.3 toolchain')
    stamp = '2026-01-01T00:00:00Z'
    advisory_id = 'GO-2099-0001'
    records = []
    for case in ('reachable', 'uncalled', 'fixed'):
        base = output / case
        source = base / 'source'
        database = base / 'synthetic-db'
        source.mkdir(parents=True)
        (database / 'index').mkdir(parents=True)
        (database / 'ID').mkdir()
        (source / 'go.mod').write_text('module example.com/scanner-compatibility\n\ngo 1.27.3\n')
        # Promoted keyed fields exercise the Go 1.27 SSA path missing in x/tools 0.29.
        call = 'exercise()' if case != 'uncalled' else '_ = http.MethodGet'
        (source / 'main.go').write_text('''package main
import "net/http"
type Inner struct { Value int }
type Outer struct { Inner }
func exercise() { client := &http.Client{}; _, _ = client.Do(nil) }
func main() { value := Outer{Value: 1}; if value.Value == 1 { ''' + call + ''' } }
''')
        fixed = '1.27.3' if case == 'fixed' else '99.0.0'
        advisory = {'schema_version': '1.3.1', 'id': advisory_id, 'modified': stamp,
            'published': stamp, 'details': 'SYNTHETIC scanner regression only; not a real vulnerability.',
            'affected': [{'package': {'name': 'stdlib', 'ecosystem': 'Go'},
                'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': fixed}]}],
                'ecosystem_specific': {'imports': [{'path': 'net/http', 'symbols': ['Client.Do']}]}}]}
        for name, value in [('index/db.json', {'modified': stamp}),
            ('index/modules.json', [{'path': 'stdlib', 'vulns': [{'id': advisory_id, 'modified': stamp, 'fixed': fixed}]}]),
            ('ID/' + advisory_id + '.json', advisory)]:
            (database / name).write_text(json.dumps(value) + '\n')
        # Exercise the real release audit coordinator and parser. Only unrelated
        # scanners/inventory are fixture stubs; govulncheck itself is the real
        # binary performing full symbol analysis against the local test DB.
        scripts = source / 'scripts'
        scripts.mkdir()
        for name in ('release-audit.py', 'source_record.py', 'go_vulnerability_gate.py'):
            shutil.copyfile(Path(__file__).parent / name, scripts / name)
        (scripts / 'release-inventory.py').write_text('print("Synthetic unrelated inventory stub")\n')
        for relative in ('apps/workspace', 'apps/workspace/tests/browser'):
            (source / relative).mkdir(parents=True, exist_ok=True)
        tools = base / 'tools'
        tools.mkdir()
        for name in ('npm', 'cargo-audit', 'trivy'):
            stub = tools / name
            stub.write_text('#!' + sys.executable + '\nprint("Synthetic unrelated scanner stub")\n')
            stub.chmod(0o755)
        wrapper = tools / 'govulncheck'
        wrapper.write_text('#!' + sys.executable + '\nimport os,sys\nos.execv(' + repr(str(binary)) + ', ['
                           + repr(str(binary)) + ', ' + repr('-db=' + database.as_uri()) + '] + sys.argv[1:])\n')
        wrapper.chmod(0o755)
        audit_output = base / 'audit'
        command = [sys.executable, '-B', str(scripts / 'release-audit.py'), str(audit_output)]
        result = subprocess.run(command, cwd=source,
            env={**environment, 'NEX_RELEASE_PROFILE': 'development', 'PATH': str(tools) + os.pathsep + environment['PATH']},
            capture_output=True, text=True, timeout=120)
        (base / 'audit.stdout').write_text(result.stdout)
        (base / 'audit.stderr').write_text(result.stderr)
        status = json.loads((audit_output / 'vulnerability-status.json').read_text())
        go_check = next(check for check in status['checks'] if check['name'] == 'go-vulnerabilities')
        if go_check.get('exit_code') != 0:
            raise ValueError('Scanner compatibility case failed: ' + case)
        events = list(messages((audit_output / 'go-vulnerabilities.stdout').read_text()))
        configs = [event['config'] for event in events if 'config' in event]
        if len(configs) != 1 or configs[0].get('scan_level') != 'symbol' or configs[0].get('scan_mode') != 'source':
            raise ValueError('Full source symbol analysis was not established')
        findings = [event['finding'] for event in events if 'finding' in event]
        calls = [finding for finding in findings if finding.get('trace', [{}])[0].get('function')]
        expected_call = case == 'reachable'
        if bool(calls) != expected_call:
            raise ValueError('Unexpected synthetic call reachability: ' + case)
        if expected_call and not any(finding.get('osv') == advisory_id and len(finding['trace']) > 1
                                    and finding['trace'][0].get('function') == 'Do'
                                    and finding['trace'][0].get('package') == 'net/http' for finding in calls):
            raise ValueError('A real imported-symbol call trace is required')
        if case == 'uncalled' and not findings:
            raise ValueError('Uncalled case must still encounter the affected imported package')
        if case == 'fixed' and findings:
            raise ValueError('Fixed-version case must have no synthetic findings')
        expected_gate = 'blocked' if expected_call else 'passed'
        if status['gate'] != expected_gate or result.returncode != (1 if expected_call else 0):
            raise ValueError('Release audit did not enforce the synthetic symbol findings: ' + case)
        records.append({'case': case, 'command': command, 'audit_exit_code': result.returncode,
                        'scanner_exit_code': go_check['exit_code'], 'audit_gate': status['gate'],
                        'findings': len(findings), 'symbol_calls': len(calls)})
    record = {'schema_version': 1, 'scope': 'Synthetic scanner compatibility only; not project vulnerability clearance',
              'toolchain': toolchain, 'scanner_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'status': 'passed', 'cases': records}
    (output / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    check(args.binary.resolve(strict=True), args.output.resolve())
