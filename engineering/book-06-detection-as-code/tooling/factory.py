"""Book 6 offline reference semantics. This is not a KQL or SPL engine."""
from __future__ import annotations
import argparse,copy,csv,hashlib,io,json,math,platform,re,statistics,sys,tarfile,time
from collections import defaultdict
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
NOW=1788955200  # 2026-09-09T12:00:00Z
HORIZON=1800
ID=re.compile(r'^[a-z0-9_.@:-]{1,120}$')
STATES={'draft','test','shadow','active','degraded','deprecated','retired'}
TRANSITIONS={'draft':{'test'},'test':{'draft','shadow'},'shadow':{'test','active','degraded'},'active':{'degraded','deprecated','shadow'},'degraded':{'shadow','deprecated'},'deprecated':{'retired','shadow'},'retired':set()}

def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False)

def digest(obj):
    return hashlib.sha256(canonical(obj).encode()).hexdigest()

def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))

def write(path,obj):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n',encoding='utf-8')

def normalize(raw):
    required=('tenant','source','event_id','event_time','ingest_time','action','outcome','principal')
    missing=[x for x in required if x not in raw]
    if missing: raise ValueError('absent:'+','.join(missing))
    if raw.get('schema_version')!=1: raise ValueError('schema_version')
    out={}
    for key in ('tenant','source','event_id','action','outcome','principal','device','session','approved_change','alias'):
        value=raw.get(key,'')
        if value is None or not isinstance(value,str):raise ValueError('type:'+key)
        # ASCII identifiers are a contract restriction, not a universal identity model.
        value=value.lower()
        if (not value and key in required) or (value and not ID.fullmatch(value)):
            raise ValueError('identifier:'+key)
        out[key]=value
    for key in ('event_time','ingest_time'):
        if type(raw[key]) is not int or raw[key]<0:raise ValueError('epoch:'+key)
        out[key]=raw[key]
    out['schema_version']=1
    out['payload_hash']=digest({k:v for k,v in out.items() if k!='ingest_time'})
    return out

def prepare(raws,now=NOW):
    rows={};conflicts=set();health=[]
    for raw in raws:
        try:e=normalize(raw)
        except ValueError as exc:
            health.append({'kind':'invalid_event','reason':str(exc),'reference':raw.get('event_id','unavailable')});continue
        if e['ingest_time']>now:continue
        if not now-HORIZON<=e['event_time']<now:continue
        key=(e['tenant'],e['source'],e['event_id'])
        if key in rows and rows[key]['payload_hash']!=e['payload_hash']:
            conflicts.add(key)
        elif key not in rows or e['ingest_time']<rows[key]['ingest_time']:rows[key]=e
    for key in sorted(conflicts):
        health.append({'kind':'conflicting_event_id','reference':'|'.join(key)});rows.pop(key,None)
    return sorted(rows.values(),key=lambda e:(e['event_time'],e['tenant'],e['source'],e['event_id'])),health

def ref(e):return '|'.join((e['tenant'],e['source'],e['event_id']))

def signal(det,events,key,mode='complete',extra=None):
    events=sorted(events,key=lambda e:(e['event_time'],ref(e)))
    obj={'detection_id':det,'version':'1.0.0','signal_key':det+'|'+key,
         'tenant':events[-1]['tenant'],'principal':events[-1]['principal'],
         'first_event_time':events[0]['event_time'],'last_event_time':events[-1]['event_time'],
         'event_refs':sorted(ref(e) for e in events),'mode':mode,
         'severity':'medium','confidence':'observed-contract-match'}
    if extra:obj.update(extra)
    return obj

def detect(det,raws,now=NOW,enrichment=None,mutation=None):
    rows,health=prepare(raws,now);out=[]
    if det=='DET-001':
        for e in rows:
            hit=e['source']=='control' and e['action']=='audit_disable' and e['outcome']=='success'
            if mutation=='widen_predicate':hit=e['source']=='control' and e['action']=='audit_disable'
            excluded=e['principal']=='svc-maint' and e['device']=='lab-maint-01' and e['approved_change']=='chg-0042'
            if mutation=='broad_exception':excluded=e['principal']=='svc-maint'
            if hit and not excluded:out.append(signal(det,[e],ref(e)))
    elif det=='DET-002':
        groups=defaultdict(list)
        for e in rows:
            if e['source']=='identity' and e['action']=='auth_denied' and e['outcome']=='failure':
                bucket=e['event_time']//300*300
                if bucket+300<=now:groups[(e['tenant'],e['principal'],bucket)].append(e)
        for (tenant,principal,bucket),events in groups.items():
            n=4 if mutation=='raise_threshold' else 3
            if len(events)>=n:out.append(signal(det,events,f'{tenant}|{principal}|{bucket}',extra={'bucket_start':bucket,'count':len(events)}))
        if mutation=='merge_buckets':
            by=defaultdict(list)
            for e in rows:
                if e['source']=='identity' and e['action']=='auth_denied' and e['outcome']=='failure':by[(e['tenant'],e['principal'])].append(e)
            out=[signal(det,v,f'{k[0]}|{k[1]}|merged',extra={'count':len(v)}) for k,v in by.items() if len(v)>=3]
    elif det=='DET-003':
        starts=[e for e in rows if e['source']=='application' and e['action']=='config_change' and e['outcome']=='success' and e['session']]
        ends=[e for e in rows if e['source']=='application' and e['action']=='archive_read' and e['outcome']=='success' and e['session']]
        for a in starts:
            for b in ends:
                keys=('tenant','principal','session')
                if not all(a[k]==b[k] for k in keys):continue
                delta=b['event_time']-a['event_time']
                valid=0<delta<=600
                if mutation=='allow_reverse':valid=abs(delta)<=600
                if mutation=='remove_upper_bound':valid=delta>0
                if mutation=='ingest_order':valid=0<b['ingest_time']-a['ingest_time']<=600
                if valid:out.append(signal(det,[a,b],ref(a)+'|'+ref(b)))
    elif det=='DET-004':
        enrichment=enrichment or {'rows':[],'observed_at':0,'version':'absent'}
        resolved=[]
        for e in rows:
            if e['source'] not in ('identity','application') or e['outcome']!='success':continue
            if e['action'] not in ('privileged_grant','export') or not e['session']:continue
            hits=[x for x in enrichment.get('rows',[]) if x['tenant']==e['tenant'] and x['alias']==e['alias'] and x['valid_from']<=e['event_time']<x['valid_to']]
            fresh=0<=now-enrichment.get('observed_at',0)<=900
            reason='fresh' if fresh and len(hits)==1 else ('stale' if not fresh else ('missing' if not hits else 'ambiguous'))
            if reason!='fresh':
                health.append({'kind':'enrichment_'+reason,'reference':ref(e),'owner':'data-owner'})
                out.append(signal(det,[e],ref(e)+'|unresolved',mode='uncorrelated',extra={'dependency_state':reason,'enrichment_version':enrichment.get('version','absent')}));continue
            resolved.append((e,hits[0]['canonical_principal']))
        for a,ap in resolved:
            if a['source']!='identity' or a['action']!='privileged_grant':continue
            for b,bp in resolved:
                if b['source']!='application' or b['action']!='export':continue
                tenant_ok=a['tenant']==b['tenant'] or mutation=='drop_tenant'
                delta=b['event_time']-a['event_time']
                time_ok=0<delta<=600
                if mutation=='ingest_order':time_ok=0<b['ingest_time']-a['ingest_time']<=600
                if tenant_ok and ap==bp and a['session']==b['session'] and time_ok:
                    out.append(signal(det,[a,b],ref(a)+'|'+ref(b),extra={'principal':ap,'enrichment_version':enrichment['version']}))
    else:raise ValueError('unknown detection')
    return {'signals':sorted(out,key=lambda x:x['signal_key']),'health':sorted(health,key=canonical)}

def contract_errors(c):
    errors=[]
    for k in ('id','uuid','version','title','owner','backup_owner','consumer','acceptance','telemetry','time','output','review_due','status'):
        if not c.get(k):errors.append('required:'+k)
    if c.get('owner')==c.get('backup_owner'):errors.append('independent_backup')
    if c.get('status') not in STATES:errors.append('status')
    if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',c.get('uuid','')):errors.append('uuid_v4')
    if c.get('time',{}).get('horizon_seconds',0)<c.get('time',{}).get('schedule_seconds',300):errors.append('horizon_schedule')
    return errors

def exception_errors(x,now=NOW):
    errors=[]
    for k in ('id','owner','approver','reason','expires','scope','positive_regression'):
        if not x.get(k):errors.append('required:'+k)
    if x.get('expires',0)<=now:errors.append('expired')
    if set(x.get('scope',{}))!={'principal','device','approved_change'}:errors.append('scope')
    if x.get('owner')==x.get('approver'):errors.append('independent_approval')
    return errors

def promote(state,target,evidence,authorized=False):
    if target not in TRANSITIONS.get(state,set()):raise ValueError('transition')
    if target in ('shadow','active'):
        if not authorized:raise ValueError('approval')
        if evidence.get('static')!='PASS' or evidence.get('unit')!='PASS':raise ValueError('local_gate')
    if target=='active' and any(evidence.get(k)!='PASS' for k in ('native','replay','rollback','health')):raise ValueError('native_gate')
    return target

def wilson(k,n,z=1.959963984540054):
    if n==0:return None
    p=k/n;den=1+z*z/n;center=(p+z*z/(2*n))/den
    half=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
    return [center-half,center+half]

def metrics(data):
    tp=data['true_positive'];fp=data['false_positive'];unknown=data['unreviewed'];n=tp+fp
    return {'adjudicated_n':n,'unreviewed_n':unknown,'precision_adjudicated':tp/n if n else None,
            'wilson_95':wilson(tp,n),'all_alert_precision_bounds': [tp/(n+unknown),(tp+unknown)/(n+unknown)] if n+unknown else None,
            'operational_recall':None,'limitation':'No known population of missed positives; selection bias remains.'}

def build_bundle(dest):
    # Bytes derive only from declared content; no timestamps or evidence-of-run included.
    dest=Path(dest);dest.parent.mkdir(parents=True,exist_ok=True)
    files=sorted(p for folder in ('catalog','detections','schemas','enrichments','fixtures','tooling','ci','deploy','metrics','docs','LICENSES') for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix not in ('.pyc',) and not ('docs' in p.parts and 'evidence' in p.parts))
    files=sorted(set(files+[ROOT/x for x in ('README.md','requirements-sigma.txt','requirements-sigma.lock') if (ROOT/x).exists()]))
    records=[];buf=io.BytesIO()
    with tarfile.open(fileobj=buf,mode='w',format=tarfile.USTAR_FORMAT) as tar:
        for p in files:
            data=p.read_bytes();name=str(p.relative_to(ROOT));info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o644;info.mtime=0
            tar.addfile(info,io.BytesIO(data));records.append({'path':name,'sha256':hashlib.sha256(data).hexdigest()})
        data=(canonical({'release':'book06-1.0.0','files':records})+'\n').encode();info=tarfile.TarInfo('manifest.json');info.size=len(data);info.mtime=0;info.mode=0o644;tar.addfile(info,io.BytesIO(data))
    dest.write_bytes(buf.getvalue());return hashlib.sha256(buf.getvalue()).hexdigest()

def signal_errors(case,result):
    errors=[];seen=set();rows,_=prepare(case['events'],case.get('now',NOW));events={ref(e):e for e in rows}
    required={'detection_id','version','signal_key','tenant','principal','first_event_time','last_event_time','event_refs','mode','severity','confidence'}
    for item in result['signals']:
        if not required<=set(item):errors.append('required_output');continue
        if item['detection_id']!=case['detection_id'] or item['version']!='1.0.0':errors.append('identity')
        if item['severity']!='medium' or item['confidence']!='observed-contract-match':errors.append('classification')
        if item['signal_key'] in seen:errors.append('duplicate_signal_key')
        seen.add(item['signal_key']);refs=item['event_refs']
        if not isinstance(refs,list) or not refs or len(refs)!=len(set(refs)):errors.append('evidence_refs');continue
        if any(x not in events for x in refs):errors.append('unknown_evidence');continue
        evidence=[events[x] for x in refs]
        if any(x['tenant']!=item['tenant'] for x in evidence):errors.append('tenant_boundary')
        if item['first_event_time']!=min(x['event_time'] for x in evidence) or item['last_event_time']!=max(x['event_time'] for x in evidence):errors.append('evidence_times')
        if item['mode']=='uncorrelated' and len(refs)!=1:errors.append('degraded_cardinality')
        if case['detection_id'] in ('DET-003','DET-004') and item['mode']=='complete' and len(refs)!=2:errors.append('pair_cardinality')
        if case['detection_id']=='DET-002' and item.get('count')!=len(refs):errors.append('count_evidence')
    return errors

def test_cases(det=None):
    cases=load(ROOT/'fixtures/cases.json');results=[]
    for case in cases:
        if det and case['detection_id']!=det:continue
        got=detect(case['detection_id'],case['events'],case.get('now',NOW),case.get('enrichment'))
        compact={'keys':[x['signal_key'] for x in got['signals']], 'modes':[x['mode'] for x in got['signals']], 'health_kinds':[x['kind'] for x in got['health']]}
        errors=signal_errors(case,got)
        results.append({'case':case['id'],'result':'PASS' if compact==case['expected'] and not errors else 'FAIL','actual':compact,'expected':case['expected'],'output_errors':errors})
    return results

def validate():
    rows=test_cases();policy=[]
    for path in sorted((ROOT/'detections').glob('*/spec/detection.json')):
        c=load(path);err=contract_errors(c);policy.append({'contract':c.get('id'),'result':'FAIL' if err else 'PASS','errors':err})
        for field in ('owner','acceptance'):
            invalid=copy.deepcopy(c);invalid.pop(field)
            policy.append({'negative':c['id']+':missing-'+field,'result':'PASS' if 'required:'+field in contract_errors(invalid) else 'FAIL'})
    matrix={'local_logic':'PASS' if all(x['result']=='PASS' for x in rows) else 'FAIL',
            'contract_policy':'PASS' if all(x['result']=='PASS' for x in policy) else 'FAIL',
            'native_kql':'NOT RUN/BLOCKED','native_spl':'NOT RUN/BLOCKED','scheduled_replay':'NOT RUN/BLOCKED',
            'production_deployment':'NOT RUN/BLOCKED'}
    report={'timestamp':datetime.now(timezone.utc).isoformat(),'python':platform.python_version(), 'fixture_sha256':hashlib.sha256((ROOT/'fixtures/cases.json').read_bytes()).hexdigest(),'command':'python tooling/factory.py validate','environment':'offline Python reference; no native SIEM', 'matrix':matrix,'cases':rows,'policy':policy}
    write(ROOT/'build/validation.json',report)
    print(canonical({'cases':len(rows),'passed':sum(x['result']=='PASS' for x in rows),'policy_checks':len(policy),'matrix':matrix}))
    return 1 if 'FAIL' in matrix.values() else 0

def mutation_test():
    operators={'DET-001':['widen_predicate','broad_exception'],'DET-002':['raise_threshold','merge_buckets'],'DET-003':['allow_reverse','remove_upper_bound','ingest_order'],'DET-004':['drop_tenant','ingest_order']}
    cases=load(ROOT/'fixtures/cases.json');report=[]
    for det,ops in operators.items():
        for op in ops:
            killed=[]
            for c in cases:
                if c['detection_id']!=det:continue
                got=detect(det,c['events'],c.get('now',NOW),c.get('enrichment'),op)
                compact={'keys':[x['signal_key'] for x in got['signals']], 'modes':[x['mode'] for x in got['signals']], 'health_kinds':[x['kind'] for x in got['health']]}
                if compact!=c['expected']:killed.append(c['id'])
            report.append({'detection_id':det,'operator':op,'killed_by':killed,'result':'killed' if killed else 'survived'})
    write(ROOT/'build/mutations.json',report);print(canonical(report));return int(any(x['result']=='survived' for x in report))

def benchmark():
    seed=load(ROOT/'fixtures/cases.json')[0]['events'][0];raw=[]
    for i in range(10000):
        e=copy.deepcopy(seed);e['event_id']=f'bench-{i:05}';e['principal']=f'user-{i%100}';raw.append(e)
    samples=[];count=0
    for _ in range(5):
        start=time.perf_counter();result=detect('DET-001',raw);samples.append(time.perf_counter()-start);count=len(result['signals'])
    report={'engine':'Python reference only','python':platform.python_version(),'platform':platform.platform(),'rows':len(raw),'matches':count,'seconds':samples,'median_seconds':statistics.median(samples),'p95_claim':None,'limitation':'Five warm local trials; neither SIEM benchmark nor representative production load.'}
    write(ROOT/'build/benchmark.json',report);print(canonical(report));return 0

def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='cmd',required=True)
    sub.add_parser('validate');sub.add_parser('mutate');sub.add_parser('benchmark')
    run=sub.add_parser('run');run.add_argument('case')
    bundle=sub.add_parser('bundle');bundle.add_argument('output')
    sub.add_parser('metrics')
    a=p.parse_args()
    if a.cmd=='validate':return validate()
    if a.cmd=='mutate':return mutation_test()
    if a.cmd=='benchmark':return benchmark()
    if a.cmd=='bundle':print(build_bundle(a.output));return 0
    if a.cmd=='metrics':print(json.dumps(metrics({'true_positive':36,'false_positive':4,'unreviewed':60}),indent=2));return 0
    if a.cmd=='run':
        c=next(c for c in load(ROOT/'fixtures/cases.json') if c['id']==a.case)
        print(json.dumps(detect(c['detection_id'],c['events'],c.get('now',NOW),c.get('enrichment')),indent=2));return 0
    return 2
if __name__=='__main__':sys.exit(main())
