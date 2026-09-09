"""Bounded local structural checks, not a vendor parser or deployment proof."""
from pathlib import Path
import json,configparser,hashlib,re
from factory import ROOT,load,write
checks=[]
def check(name,ok):checks.append({'name':name,'result':'PASS' if ok else 'FAIL'})
for d in sorted((ROOT/'detections').glob('DET-*')):
 c=load(d/'spec/detection.json');check(d.name+' contract mirrors YAML',load(d/'spec/detection.yaml')==c)
 k=(d/'kql/scheduled.kql').read_text();s=(d/'spl/scheduled.spl').read_text()
 resource=load(d/'release/sentinel.json')['resources'][0];props=resource['properties']
 check(d.name+' disabled scheduled ARM resource',resource['kind']=='Scheduled' and resource['apiVersion']=='2025-09-01' and props['enabled'] is False)
 check(d.name+' ARM query source equality',props['query']==k)
 check(d.name+' schedule and horizon',props['queryFrequency']=='PT5M' and props['queryPeriod']=='PT30M')
 check(d.name+' per-result candidate threshold',props['triggerThreshold']==0 and props['triggerOperator']=='GreaterThan')
 conf=configparser.ConfigParser(interpolation=None);conf.read(d/'release/savedsearches.conf');sec=conf[conf.sections()[0]]
 check(d.name+' disabled saved search',sec['disabled']=='1' and sec['actions']=='')
 check(d.name+' SPL source equality',sec['search'].strip()==s.replace('\n',' ').strip())
 check(d.name+' declared output keys',all(x in k and x in s for x in c['output']['required']))
for case in load(ROOT/'fixtures/cases.json'):
 check(case['id']+' explicit expectation',set(case['expected'])=={'keys','modes','health_kinds'})
write(ROOT/'build/static.json',{'checks':checks,'scope':'local policy and file consistency; no official service schema acceptance or native query parsing'})
print(json.dumps({'checks':len(checks),'passed':sum(x['result']=='PASS' for x in checks),'native_query_parsing':'NOT RUN/BLOCKED'}))
raise SystemExit(any(x['result']=='FAIL' for x in checks))
