"""Pinned Sigma candidate conversion, never deployment."""
from pathlib import Path
import json,importlib.metadata
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline
from sigma.backends.splunk import SplunkBackend
from sigma.backends.kusto import KustoBackend
R=Path(__file__).resolve().parents[1]
rule=R/'detections/DET-001/sigma/intent.yml';out=R/'build/conversion';out.mkdir(parents=True,exist_ok=True)
report={'packages':{p:importlib.metadata.version(p) for p in ['sigma-cli','pysigma','pysigma-backend-splunk','pysigma-backend-kusto']},'native_execution':'NOT RUN/BLOCKED','outputs':{}}
for name,backend,ext in [('splunk',SplunkBackend,'spl'),('kusto',KustoBackend,'kql')]:
 pipeline=ProcessingPipeline.from_yaml((R/f'ci/sigma-{name}.yml').read_text())
 result=backend(processing_pipeline=pipeline).convert(SigmaCollection.from_yaml(rule.read_text()))
 (out/f'candidate.{ext}').write_text('\n'.join(result)+'\n');report['outputs'][name]=result
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
