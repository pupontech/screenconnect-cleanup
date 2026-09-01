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
# This test exercises diff semantics, not Linux platform collection failures.
# Normalize the historical fixture to an explicitly complete snapshot; the
# incomplete verdict is tested separately below.
before['CollectionErrors'] = []
before['CollectionWarnings'] = []
before['CollectionComplete'] = True
after['CollectionErrors'] = []
after['CollectionWarnings'] = []
after['CollectionComplete'] = True

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
# 5) Nested/array field changes must be compared structurally, not by the
#    PowerShell string representation of System.Object[].
S['Services'].append({'Key': 'SynthArray', 'Tags': ['old']})
after['Sections']['Services'].append({'Key': 'SynthArray', 'Tags': ['new']})
# 6) An empty JSON object is the Windows PowerShell 5.1 serialization of an
#    empty collection and must count as zero.
before['Sections']['Amcache'] = {}
after['Sections']['Amcache'] = {}
# 7) Forensic-history additions are informational, not resurrection signals.
after['Sections']['Prefetch'].append({'Key': 'synth-history.pf', 'Path': 'C:\\\\synth-history.exe'})

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

# A recorded collection failure must override otherwise interesting section
# changes, because empty placeholders cannot prove absence.
incomplete_after = copy.deepcopy(after)
incomplete_after['CollectionComplete'] = False
incomplete_after['CollectionErrors'] = [{'Section': 'Services', 'Error': 'synthetic timeout'}]
incomplete_path = os.path.join(tmp, 'synth-after-incomplete.json')
incomplete_diff_path = os.path.join(tmp, 'synth-diff-incomplete.json')
json.dump(incomplete_after, open(incomplete_path, 'w'))
r_incomplete = subprocess.run([pwsh, '-NoProfile', '-File', './diff-snapshots.ps1',
                               '-BeforeFile', b_path, '-AfterFile', incomplete_path,
                               '-OutFile', incomplete_diff_path], capture_output=True, text=True)
d_incomplete = json.load(open(incomplete_diff_path))
checks = {
    'verdict RESURRECTION': d['Verdict'] == 'RESURRECTION',
    'incomplete collection verdict': d_incomplete['Verdict'] == 'INCOMPLETE' and r_incomplete.returncode == 1,
    'resurrection count 1': d['ResurrectionsAdded'] == 1,
}
svc = next(s for s in d['Sections'] if s['Section']=='Services')
st  = next(s for s in d['Sections'] if s['Section']=='ScheduledTasks')
ra  = next(s for s in d['Sections'] if s['Section']=='RegistryAutoruns')
pr  = next(s for s in d['Sections'] if s['Section']=='Processes')
am  = next(s for s in d['Sections'] if s['Section']=='Amcache')
pf  = next(s for s in d['Sections'] if s['Section']=='Prefetch')
checks['services removed list'] = svc['Removed'] == ['ScreenConnect Client (synth)']
checks['tasks added list'] = st['Added'] == ['\\\\Synth\\\\PersistTask'.replace('\\\\','\\')]
checks['autoruns changed field'] = any(c.get('Fields')==['Value'] for c in ra['Changed'])
checks['volatile added not counted as resurrection'] = pr['Kind']=='volatile' and len(pr['Added'])==1 and d['ResurrectionsAdded']==1
checks['nested array field changed structurally'] = any(c.get('Key') == 'SynthArray' and c.get('Fields') == ['Tags'] for c in svc['Changed'])
checks['empty object counts as zero'] = am['BeforeCount'] == 0 and am['AfterCount'] == 0 and not am['Added'] and not am['Removed']
checks['forensic history is informational'] = pf['Kind'] == 'informational' and pf['Added'] == ['synth-history.pf'] and d['ResurrectionsAdded'] == 1
ok = all(checks.values())
for k,v in checks.items(): print(('PASS' if v else 'FAIL'), k)
sys.exit(0 if ok else 1)
