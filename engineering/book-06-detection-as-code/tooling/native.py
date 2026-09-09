"""Export inert fixtures and compare supplied native results. No remote execution."""
import argparse,json,sys,copy,csv
from pathlib import Path
from factory import ROOT,NOW,load,write,normalize,detect,canonical,prepare
FIELDS=('detection_id','version','signal_key','tenant','principal','first_event_time','last_event_time','event_refs','mode','severity','confidence')

def normalized(row):
    missing=[x for x in FIELDS if x not in row]
    if missing:raise ValueError('missing output fields: '+','.join(missing))
    extra=[]
    if row['detection_id']=='DET-002':extra=['count','bucket_start']
    if row['detection_id']=='DET-004':extra=['enrichment_version']+(['dependency_state'] if row['mode']=='uncorrelated' else [])
    if any(x not in row for x in extra):raise ValueError('missing product-specific output fields')
    out={x:row[x] for x in (*FIELDS,*extra)}
    for x in ('count','bucket_start'):
        if x in out:out[x]=int(out[x])
    for x in ('first_event_time','last_event_time'):out[x]=int(out[x])
    refs=out['event_refs']
    if isinstance(refs,str):
        if refs.startswith('['):refs=json.loads(refs)
        else:refs=[refs]
    if not isinstance(refs,list) or not all(isinstance(x,str) for x in refs):raise ValueError('event_refs')
    out['event_refs']=sorted(refs)
    return out

def export(case,dest,shift=0):
    if shift % 300:raise ValueError('shift must preserve five-minute UTC bucket alignment')
    dest=Path(dest);dest.mkdir(parents=True,exist_ok=True);rows=[];rejected=[]
    for raw in case['events']:
        e=copy.deepcopy(raw)
        for x in ('event_time','ingest_time'):
            if type(e.get(x)) is int:e[x]+=shift
        try:n=normalize(e)
        except ValueError as exc:rejected.append({'raw':e,'reason':str(exc)});continue
        n['quality']='valid';n['TimeGenerated']=__import__('datetime').datetime.fromtimestamp(n['event_time'],__import__('datetime').timezone.utc).isoformat();rows.append(n)
    write(dest/'kql-input.json',rows)
    spl=[dict(x,source_kind=x['source']) for x in rows]
    for x in spl:x.pop('source')
    (dest/'spl-input.jsonl').write_text(''.join(canonical(x)+'\n' for x in spl))
    write(dest/'rejected.json',rejected)
    write(dest/'replay-plan.json',{'case':case['id'],'shift_seconds':shift,'evaluation_epoch':case.get('now',NOW)+shift,'native_status':'NOT RUN/BLOCKED','instructions':'Ingest only in an authorized isolated target; bind the stated evaluation clock; preserve future-ingestion availability; inspect query and scheduled output separately.'})
    if 'enrichment' in case:
        en=copy.deepcopy(case['enrichment']);en['observed_at']+=shift
        for r in en['rows']:r['valid_from']+=shift;r['valid_to']+=shift
        write(dest/'enrichment.json',en)
        resolved=[]
        eligible,_=prepare([dict(x,quality='valid') for x in rows],case.get('now',NOW)+shift)
        for row in eligible:
            hits=[a for a in en['rows'] if a['tenant']==row['tenant'] and a['alias']==row['alias'] and a['valid_from']<=row['event_time']<a['valid_to']]
            fresh=0<=case.get('now',NOW)+shift-en['observed_at']<=900
            state='fresh' if fresh and len(hits)==1 else 'stale' if not fresh else 'missing' if not hits else 'ambiguous'
            resolved.append({'event_ref':'|'.join(row[k] for k in ('tenant','source','event_id')),'canonical_principal':hits[0]['canonical_principal'] if len(hits)==1 else '', 'dependency_state':state,'enrichment_version':en['version'],'resolution_epoch':case.get('now',NOW)+shift})
        with (dest/'book06_resolution.csv').open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=['event_ref','canonical_principal','dependency_state','enrichment_version','resolution_epoch']);w.writeheader();w.writerows(resolved)
    print('Exported fixture plan; no native execution performed.')

def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='cmd',required=True)
    e=sub.add_parser('export');e.add_argument('case');e.add_argument('directory');e.add_argument('--shift-seconds',type=int,default=0)
    c=sub.add_parser('compare');c.add_argument('case');c.add_argument('actual');c.add_argument('--target',required=True,choices=['kql','spl']);c.add_argument('--shift-seconds',type=int,default=0)
    a=p.parse_args();case=next(x for x in load(ROOT/'fixtures/cases.json') if x['id']==a.case)
    if a.cmd=='export':export(case,a.directory,a.shift_seconds);return 0
    if not Path(a.actual).is_file():print('NOT RUN/BLOCKED: native output file unavailable');return 2
    if a.shift_seconds % 300:raise ValueError('shift must preserve five-minute UTC bucket alignment')
    if a.shift_seconds:
        case=copy.deepcopy(case);case['now']=case.get('now',NOW)+a.shift_seconds
        for e in case['events']:
            for field in ('event_time','ingest_time'):
                if type(e.get(field)) is int:e[field]+=a.shift_seconds
        if 'enrichment' in case:
            case['enrichment']['observed_at']+=a.shift_seconds
            for row in case['enrichment']['rows']:
                row['valid_from']+=a.shift_seconds;row['valid_to']+=a.shift_seconds
    # Reference provides expected output; supplied native file is never invented.
    expected=sorted((normalized(x) for x in detect(case['detection_id'],case['events'],case.get('now',NOW),case.get('enrichment'))['signals']),key=canonical)
    actual=sorted((normalized(x) for x in load(a.actual)),key=canonical)
    report={'target':a.target,'case':a.case,'result':'PASS' if expected==actual else 'FAIL','expected':expected,'actual':actual,'scope':'supplied query-result conformance only; no claim of scheduler or resource proof'}
    write(ROOT/f'build/native-{a.target}-{a.case}.json',report);print(json.dumps(report,indent=2));return int(expected!=actual)
if __name__=='__main__':raise SystemExit(main())
