"""Offline policy and delivery simulations; never applies cloud or SIEM changes."""
import copy,json,tempfile
from pathlib import Path
from factory import ROOT,NOW,load,write,exception_errors,promote,build_bundle,metrics,detect

def main():
 results=[]
 def check(name,ok):results.append({'name':name,'result':'PASS' if ok else 'FAIL'})
 def denied(fn):
  try:fn();return False
  except ValueError:return True
 ex=load(ROOT/'catalog/exception.json');check('valid scoped exception',not exception_errors(ex))
 expired=copy.deepcopy(ex);expired['expires']=NOW;check('expiry is exclusive','expired' in exception_errors(expired))
 broad=copy.deepcopy(ex);broad['scope']={'principal':'svc-maint'};check('broad exception denied','scope' in exception_errors(broad))
 evidence={'static':'PASS','unit':'PASS','native':'NOT RUN/BLOCKED','replay':'NOT RUN/BLOCKED'}
 check('unauthorized promotion denied',denied(lambda:promote('test','shadow',evidence,False)))
 check('active without native proof denied',denied(lambda:promote('shadow','active',evidence,True)))
 check('retired cannot reactivate',denied(lambda:promote('retired','active',evidence,True)))
 check('authorized shadow boundary',promote('test','shadow',evidence,True)=='shadow')
 # Demonstration only: a simulated health failure restores a stored prior identity.
 state={'active':'new','prior':'known-good','health':'failed'}
 if state['health']=='failed':state['active']=state['prior']
 check('rollback state simulation',state['active']=='known-good')
 # Candidate delivery deduplication is separate from native query execution.
 c=load(ROOT/'fixtures/cases.json')[0];ledger=set();delivered=[]
 for _ in range(2):
  for s in detect(c['detection_id'],c['events'])['signals']:
   if s['signal_key'] not in ledger:ledger.add(s['signal_key']);delivered.append(s)
 check('overlap consumer simulation',len(delivered)==1)
 with tempfile.TemporaryDirectory() as tmp:
  a=build_bundle(Path(tmp)/'a.tar');b=build_bundle(Path(tmp)/'b.tar');check('deterministic package',a==b)
 m=metrics(load(ROOT/'metrics/sample.json'));check('precision denominator',m['precision_adjudicated']==0.9)
 check('missing labels bounds',m['all_alert_precision_bounds']==[0.36,0.96])
 rows=load(ROOT/'metrics/dispositions.json');accepted=[x for x in rows if x['evidence'] and x['confidence']=='reviewed'];check('low evidence feedback rejected',len(accepted)==3)
 case=next(x for x in load(ROOT/'fixtures/cases.json') if x['id']=='correlation-stale');health=detect('DET-004',case['events'],enrichment=case['enrichment'])['health'];check('stale enrichment owner route',len(health)==2 and all(x['owner']=='data-owner' for x in health))
 overlays=[load(ROOT/f'deploy/{x}.json') for x in ('dev','stage','prod')];check('all deployment overlays disabled',all(not x['enabled'] and x['mode']=='dry-run' for x in overlays))
 write(ROOT/'build/controls.json',{'checks':results,'scope':'offline policy and state simulations only'});print(json.dumps(results,indent=2));return int(any(x['result']=='FAIL' for x in results))
if __name__=='__main__':raise SystemExit(main())
