"""Focused regression checks for adapter/output and disabled-plan boundaries."""
import copy,json,tempfile
from pathlib import Path
from factory import ROOT,load,detect,signal_errors,NOW,write
from native import export
from delivery import plan
checks=[]
def check(name,value):
    checks.append({'name':name,'result':'PASS' if value else 'FAIL'})
cases=load(ROOT/'fixtures/cases.json');c=next(x for x in cases if x['id']=='single-positive');r=detect(c['detection_id'],c['events']);bad=copy.deepcopy(r);bad['signals'][0].pop('principal');check('missing output field rejected','required_output' in signal_errors(c,bad))
bad=copy.deepcopy(r);bad['signals'][0]['last_event_time']+=1;check('evidence timestamp mutation rejected','evidence_times' in signal_errors(c,bad))
with tempfile.TemporaryDirectory() as tmp:
    c=next(x for x in cases if x['id']=='correlation-fresh');d=copy.deepcopy(c);d['events']+=copy.deepcopy(d['events']);export(d,tmp,300)
    rows=(Path(tmp)/'book06_resolution.csv').read_text().splitlines();check('resolution keys deduplicated',len(rows)==3)
    check('shifted clock recorded',load(Path(tmp)/'replay-plan.json')['evaluation_epoch']==NOW+300)
    try:export(c,tmp,1);check('unaligned shift rejected',False)
    except ValueError:check('unaligned shift rejected',True)
for env in ('dev','stage','prod'):check('disabled zero-write plan '+env,plan(env)['remote_operations']==0 and plan(env)['enabled'] is False)
try:plan('unknown');check('unknown environment rejected',False)
except ValueError:check('unknown environment rejected',True)
write(ROOT/'build/review-checks.json',checks);print(json.dumps(checks,indent=2));raise SystemExit(any(x['result']=='FAIL' for x in checks))
