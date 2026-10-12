"""Synthetic schema/runtime parity proof. Never installs or executes payloads."""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from jsonschema import validators


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--powershell', default='pwsh')
    parser.add_argument('--legacy-array-output', action='store_true',
                        help='Exercise the legacy non-enumerating JSON-array output contract')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[3]
    schema = json.loads((Path(__file__).with_name('protected-install-manifest.schema.json')).read_text())
    validator_type = validators.validator_for(schema)
    validator_type.check_schema(schema)
    schema_validator = validator_type(schema)
    file_schema = schema['properties']['files']
    per_member_limit = file_schema['items']['properties']['size']['maximum']
    assert file_schema['maxItems'] * per_member_limit <= 67108864, 'Schema-valid payloads can exceed the runtime aggregate cap'
    payload = b'synthetic protected module - not executable'
    name = 'payload/ProtectedEvidence.ps1'
    members = {name: base64.b64encode(payload).decode('ascii')}
    template = {
        'schemaVersion': 1,
        'component': 'ScreenConnectCleanup.Protected',
        'version': '1.0.0',
        'files': [{'path': name, 'sha256': hashlib.sha256(payload).hexdigest(), 'size': len(payload)}],
    }
    cases = []

    def add(label, manifest, accepted, code=None, escaped_slashes=False):
        text = json.dumps(manifest, separators=(',', ':'), ensure_ascii=True)
        if escaped_slashes:
            text = text.replace('/', '\\/')
        cases.append({'label': label, 'manifestText': text, 'payloads': members,
                      'accepted': accepted, 'code': code})

    add('canonical manifest', template, True)
    for version, accepted in [('0.0.0', True), ('65535.65535.65535', True),
                              ('65536.0.0', False), ('0.65536.0', False),
                              ('0.0.65536', False), ('01.0.0', False),
                              ('-1.0.0', False)]:
        item = copy.deepcopy(template)
        item['version'] = version
        add('version ' + version, item, accepted)
    for value, accepted in [(1.0, True), (1.5, False), ('1', False), (True, False), (2, False)]:
        item = copy.deepcopy(template)
        item['schemaVersion'] = value
        add('schema numeric ' + repr(value), item, accepted)
    for value, accepted in [(float(len(payload)), True), (len(payload) + 0.5, False),
                            (str(len(payload)), False), (True, False), (0, False),
                            (per_member_limit + 1, False)]:
        item = copy.deepcopy(template)
        item['files'][0]['size'] = value
        add('size numeric ' + repr(value), item, accepted)
    duplicate = copy.deepcopy(template)
    extra = copy.deepcopy(duplicate['files'][0])
    extra['sha256'] = hashlib.sha256(b'different synthetic bytes').hexdigest()
    duplicate['files'].append(extra)
    add('duplicate path differing records', duplicate, False)
    for value in ['1"2', '1\\2']:
        item = copy.deepcopy(template)
        item['version'] = value
        add('legal JSON escape ' + repr(value), item, False, 'INVALID_VERSION')
    add('escaped slash in allowed path', template, True, escaped_slashes=True)

    powershell = shutil.which(args.powershell)
    if powershell is None:
        raise RuntimeError('Requested PowerShell executable is unavailable')
    scratch = os.environ.get('TMPDIR') or os.environ.get('RUNNER_TEMP')
    if not scratch:
        scratch = '/root/.hermes/cache/scratch' if os.name != 'nt' else os.environ['TEMP']
    Path(scratch).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='manifest-parity-', dir=scratch) as tmp:
        folder = Path(tmp)
        fixtures = folder / 'fixtures.json'
        fixtures.write_text(json.dumps(cases, ensure_ascii=True), encoding='utf-8')
        probe = folder / 'probe.ps1'
        probe.write_text("""[CmdletBinding()]
param([string]$ValidatorPath, [string]$FixturesPath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. $ValidatorPath
$cases = Get-Content -LiteralPath $FixturesPath -Raw | ConvertFrom-Json
$results = @()
foreach ($case in $cases) {
    $encoding = New-Object System.Text.UTF8Encoding($false, $true)
    $bytes = $encoding.GetBytes([string]$case.manifestText)
    $map = [System.Collections.Generic.Dictionary[string, byte[]]]::new([StringComparer]::Ordinal)
    foreach ($entry in $case.payloads.PSObject.Properties) {
        $map.Add($entry.Name, [Convert]::FromBase64String([string]$entry.Value))
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $digest = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    $result = Test-ProtectedInstallManifest -ManifestBytes $bytes -ExpectedManifestSha256 $digest -PayloadBytesByPath $map
    if ($result.InstallationAuthorized -or $result.RemovalAuthorized -or $result.PublisherAuthenticated) {
        throw 'Pure validator incorrectly claimed authority.'
    }
    $results += [pscustomobject]@{ label = $case.label; accepted = $result.IntegrityVerified; code = $result.FailureCode }
}
ConvertTo-Json -InputObject @($results) -Depth 4 -Compress
""", encoding='ascii')
        if args.legacy_array_output:
            # This shim exercises collection shape, not native PS5.1 compatibility.
            shim = r'''function ConvertFrom-Json {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline = $true)][string]$InputObject)
    process {
        $decoded = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject
        Write-Output -NoEnumerate $decoded
    }
}
'''
            text = probe.read_text(encoding='ascii')
            text = text.replace('. $ValidatorPath\n', shim + '. $ValidatorPath\n', 1)
            probe.write_text(text, encoding='ascii')
        run = subprocess.run([powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(probe),
                              '-ValidatorPath', str(repo / 'gui-bridge/ProtectedInstallManifest.ps1'),
                              '-FixturesPath', str(fixtures)], capture_output=True, text=True,
                             timeout=120, cwd=repo)
        if run.returncode:
            raise RuntimeError(run.stdout + run.stderr)
        results = json.loads(run.stdout.strip())
    failures = []
    assert len(results) == len(cases)
    for case, result in zip(cases, results):
        schema_accepts = not list(schema_validator.iter_errors(json.loads(case['manifestText'])))
        if schema_accepts != case['accepted'] or result['accepted'] != case['accepted']:
            failures.append({'label': case['label'], 'expected': case['accepted'],
                             'schema': schema_accepts, 'runtime': result['accepted'], 'code': result['code']})
        if case['code'] and result['code'] != case['code']:
            failures.append({'label': case['label'], 'expected_code': case['code'], 'actual_code': result['code']})
    if failures:
        raise AssertionError(json.dumps(failures, indent=2))
    print('PASS: {} schema/runtime parity cases; legal JSON escapes verified; no authority or host mutation.'.format(len(cases)))


if __name__ == '__main__':
    main()
