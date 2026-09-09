"""Deterministic synthetic cohort for Chapter 14; no production-rate claim."""
import copy,json
from factory import ROOT,load,detect,write
seed=next(c for c in load(ROOT/'fixtures/cases.json') if c['id']=='single-positive')['events'][0]
rows=[]
for i in range(100):
    e=copy.deepcopy(seed);e['event_id']=f'tuning-{i:03}'
    if i<40:e.update(principal='svc-maint',device='lab-maint-01',approved_change='chg-0042')
    elif i<70:e.update(principal='svc-maint',device='lab-other-01',approved_change='chg-0042')
    else:e.update(principal=f'user-{i:03}',device='lab-user-01',approved_change='')
    rows.append(e)
raw=rows+copy.deepcopy(rows[40:60])
exact=detect('DET-001',raw);broad=detect('DET-001',raw,mutation='broad_exception')
expected={f'DET-001|{e["tenant"]}|{e["source"]}|{e["event_id"]}' for e in rows[40:]}
exact_keys={x['signal_key'] for x in exact['signals']};broad_keys={x['signal_key'] for x in broad['signals']}
assert exact_keys==expected and broad_keys<expected and len(broad_keys)==30
report={'population':'authored synthetic cohort; not a production sample','raw_deliveries':len(raw),'unique_events':len(rows),'approved_maintenance':40,'same_actor_other_device':30,'other_principals':30,'expected_positive_keys':sorted(expected),'exact_exception_candidates':len(exact_keys),'broad_exception_candidates':len(broad_keys),'known_positive_keys_lost_by_broad_exception':sorted(expected-broad_keys),'local_result':'PASS','native_result':'NOT RUN/BLOCKED','limitation':'Contract-positive preservation only; no incident labels, prevalence, or production alert-load estimate.'}
write(ROOT/'build/tuning.json',report);print(json.dumps({k:v for k,v in report.items() if not k.endswith('keys') and not isinstance(v,list)},indent=2))
