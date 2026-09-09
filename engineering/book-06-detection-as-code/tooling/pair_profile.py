"""Small disclosed Python pair-cardinality profile, not a native SIEM benchmark."""
import copy,json,platform,statistics,time
from factory import ROOT,load,detect,NOW,write
seed=next(c for c in load(ROOT/'fixtures/cases.json') if c['id']=='sequence-ordered')['events'][0]
reports=[]
for starts,ends,groups in [(1,1,1),(10,10,1),(100,100,1),(250,250,1),(250,250,10)]:
    rows=[]
    for kind,n,action,epoch in [('s',starts,'config_change',NOW-500),('e',ends,'archive_read',NOW-100)]:
        for i in range(n):
            e=copy.deepcopy(seed);e.update(event_id=f'profile-{kind}-{i:03}',action=action,event_time=epoch,ingest_time=NOW-10,session=f'session-{i%groups:02}');rows.append(e)
    expected=sum(sum(1 for i in range(starts) if i%groups==g)*sum(1 for i in range(ends) if i%groups==g) for g in range(groups));times=[]
    for _ in range(3):
        t=time.perf_counter();result=detect('DET-003',rows);times.append(time.perf_counter()-t);assert len(result['signals'])==expected
    reports.append({'starts':starts,'ends':ends,'session_groups':groups,'input_rows':len(rows),'expected_pairs':expected,'actual_pairs':len(result['signals']),'seconds':times,'median_seconds':statistics.median(times)})
report={'engine':'Python reference only','python':platform.python_version(),'platform':platform.platform(),'trials_per_shape':3,'results':reports,'limitation':'Synthetic in-process trials; no native query plan, memory profile, service concurrency, or production-cost claim.'};write(ROOT/'build/pair-profile.json',report);print(json.dumps(report,indent=2))
