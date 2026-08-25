#!/usr/bin/env python3
"""Synthetic Stage 7 test: inject items into the real snapshots so the diff
Removed/Added/Changed paths get exercised end-to-end via pwsh.

Runs locally and in CI. On Windows CI the temp dir is %RUNNER_TEMP%
(passed via SCC_TEST_TMP); default /tmp keeps local Linux behavior.
"""
import json, copy, os, subprocess, sys, tempfile

tmp = os.environ.get('SCC_TEST_TMP') or tempfile.gettempdir()
pwsh = 'powershell.exe' if os.name == 'nt' else 'pwsh'

def load(p):
    return json.load(open(p))

before = load('snapshots/before.json')
after = copy.deepcopy(before)

S = before['Sections']

# Stable sections
# 1) Service REMOVED after (proof-of-removal path)
S['Services'].append({'Key': 'ScreenConnect Client (synth)', 'Name': 'ScreenConnect Client (synth)', 'State': 'Running', 'StartMode': 'Auto'})
# 2) Scheduled task RESURRECTED in after (added-in-stable -> verdict RESURRECTION)
after['Sections']['ScheduledTasks'].append({'Key': '\\Synth\\PersistTask', 'TaskPath': '\\Synth\\', 'TaskName': 'PersistTask'})
# 3) Registry autorun CHANGED value in after
S['RegistryAutoruns'].append({'Key': 'HKCU\\...\\Run|SynthVal', 'Value': 'C:\\legit.exe'})
after['Sections']['RegistryAutoruns'].append({'Key': 'HKCU\\...\\Run|SynthVal', 'Value': 'C:\\evil2.exe'})
# 4) Volatile section: process added+removed (should NOT flip verdict)
S['Processes'].append({'Key': '1234', 'Name': 'oldproc.exe'})
after['Sections']['Processes'].append({'Key': '9999', 'Name': 'newproc.exe'})

b_path = os.path.join(tmp, 'synth-before.json')
a_path = os.path.join(tmp, 'synth-after.json')
d_path = os.path.join(tmp, 'synth-diff.json')
json.dump(before, open(b_path, 'w'))
json.dump(after, open(a_path, 'w'))

r = subprocess.run([pwsh, '-NoProfile', '-File', './diff-snapshots.ps1',
                    '-BeforeFile', b_path, '-AfterFile', a_path,
                    '-OutFile', d_path], capture_output=True, text=True)
print(r.stdout)
print(r.stderr)
print('rc =', r.returncode)
d = json.load(open(d_path))
checks = {
    'verdict RESURRECTION': d['Verdict'] == 'RESURRECTION',
    'resurrection count 1': d['ResurrectionsAdded'] == 1,
}
svc = next(s for s in d['Sections'] if s['Section']=='Services')
st  = next(s for s in d['Sections'] if s['Section']=='ScheduledTasks')
ra  = next(s for s in d['Sections'] if s['Section']=='RegistryAutoruns')
pr  = next(s for s in d['Sections'] if s['Section']=='Processes')
checks['services removed list'] = svc['Removed'] == ['ScreenConnect Client (synth)']
checks['tasks added list'] = st['Added'] == ['\\\\Synth\\\\PersistTask'.replace('\\\\','\\')]
checks['autoruns changed field'] = any(c.get('Fields')==['Value'] for c in ra['Changed'])
checks['volatile added not counted as resurrection'] = pr['Kind']=='volatile' and len(pr['Added'])==1 and d['ResurrectionsAdded']==1
ok = all(checks.values())
for k,v in checks.items(): print(('PASS' if v else 'FAIL'), k)
sys.exit(0 if ok else 1)
