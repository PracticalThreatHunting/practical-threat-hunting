"""Disabled deployment planning only; no remote-write capability."""
import argparse,hashlib,json
from factory import ROOT,load,write
ALLOWED={'enabled','environment','horizon_seconds','index','mode','schedule_seconds','workspace'}
def plan(name):
    if name not in ('dev','stage','prod'):raise ValueError('unknown_environment')
    overlay=load(ROOT/'deploy'/f'{name}.json')
    if set(overlay)!=ALLOWED:raise ValueError('overlay_keys')
    if overlay['mode']!='dry-run' or overlay['enabled'] is not False:raise ValueError('disabled_only')
    if overlay['environment']!=name:raise ValueError('environment_mismatch')
    if overlay['schedule_seconds']!=300 or overlay['horizon_seconds']!=1800:raise ValueError('behavioral_override')
    if any(not isinstance(overlay[k],str) or not overlay[k] for k in ('workspace','index')):raise ValueError('destination_binding')
    files=[]
    for p in sorted((ROOT/'detections').glob('*/release/*')):
        files.append({'path':str(p.relative_to(ROOT)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'action':'inspect_disabled_candidate'})
    return {'environment':name,'mode':'dry-run','remote_operations':0,'enabled':False,'overlay':overlay,'resources':files,'status':'PLAN ONLY; native destination authorization and validation required','signature_status':'UNSIGNED'}
def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['plan']);p.add_argument('--environment',choices=['dev','stage','prod'],default='dev');a=p.parse_args()
    result=plan(a.environment);write(ROOT/'build'/f'plan-{a.environment}.json',result);print(json.dumps(result,indent=2))
if __name__=='__main__':main()
