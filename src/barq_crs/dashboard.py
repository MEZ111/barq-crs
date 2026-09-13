from __future__ import annotations

from datetime import datetime, timezone
from html import escape
import json
from typing import Any, Iterable

from .fusion import RankedCandidate


def main() -> None:
    import argparse
    from pathlib import Path
    from .fusion import SignalFusion
    from .models import Candidate, Evidence

    parser = argparse.ArgumentParser(description="Offline review of saved BARQ results")
    parser.add_argument("candidates")
    parser.add_argument("--output", default="review.html")
    args = parser.parse_args()
    values = json.loads(Path(args.candidates).read_text(encoding="utf-8"))
    candidates = []
    for value in values:
        value = dict(value)
        value.pop("score", None)
        value["evidence"] = tuple(Evidence(**item) for item in value.get("evidence", []))
        candidates.append(Candidate(**value))
    report = html_dashboard(SignalFusion().rank(candidates), "Security review")
    with Path(args.output).open("x", encoding="utf-8") as handle:
        handle.write(report)
    print(str(Path(args.output).resolve()))


def _safe_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")


def html_dashboard(
    items: Iterable[RankedCandidate],
    campaign: str,
    *,
    schema_tests: Iterable[dict[str, Any]] = (),
    api_sequences: Iterable[dict[str, Any]] = (),
    discovery: dict[str, Any] | None = None,
    generated: str | None = None,
) -> str:
    """Build a dependency-free, offline review dashboard.

    The dashboard embeds only already-sanitized candidate/test metadata. It has
    no network imports and renders dynamic values through ``textContent``.
    """

    ranked = list(items)
    tests = list(schema_tests)
    sequences = list(api_sequences)
    generated_at = generated or datetime.now(timezone.utc).isoformat(timespec="seconds")
    findings = []
    for item in ranked:
        candidate = item.candidate
        findings.append(
            {
                "id": candidate.id,
                "title": candidate.title,
                "target": candidate.target,
                "severity": candidate.severity.lower(),
                "score": item.priority_score,
                "engine": candidate.engine,
                "engines": list(item.corroborating_engines),
                "signals": item.target_signal_count,
                "next": candidate.safe_next_step,
                "remediation": candidate.remediation_hint,
                "evidence": [
                    {
                        "kind": evidence.kind,
                        "summary": evidence.summary,
                        "fingerprint": evidence.fingerprint[:16],
                    }
                    for evidence in candidate.evidence
                ],
            }
        )
    severity_counts = {
        severity: sum(item["severity"] == severity for item in findings)
        for severity in ("critical", "high", "medium", "low", "info")
    }
    payload = {
        "campaign": campaign,
        "generated": generated_at,
        "findings": findings,
        "tests": tests,
        "sequences": sequences,
        "discovery": discovery or {},
    }
    campaign_text = escape(str(campaign), quote=True)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>BARQ Autopilot — {campaign_text}</title>
  <style>
    :root {{ --bg:#07110f; --panel:#0d1a17; --panel2:#12231f; --line:#244139; --text:#effcf7; --muted:#91aa9f; --lime:#84f7bd; --cyan:#72d9ff; --amber:#ffca68; --red:#ff6b78; }}
    * {{ box-sizing:border-box }} body {{ margin:0; background:radial-gradient(circle at 85% 0,#123b2e 0,transparent 30rem),var(--bg); color:var(--text); font:15px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace }}
    button,input,select {{ font:inherit }} .shell {{ max-width:1480px; margin:auto; padding:28px }}
    header {{ display:flex; align-items:flex-end; justify-content:space-between; gap:24px; margin-bottom:22px }}
    .mark {{ color:var(--lime); letter-spacing:.18em; font-weight:800; font-size:13px }} h1 {{ font:700 clamp(28px,5vw,54px)/1.02 system-ui,sans-serif; margin:7px 0 }}
    .sub,.muted {{ color:var(--muted) }} .notice {{ max-width:520px; border:1px solid #735c2c; background:#2b2414; color:#ffe2a3; padding:12px 14px; border-radius:10px }}
    .metrics {{ display:grid; grid-template-columns:repeat(6,minmax(110px,1fr)); gap:10px; margin:18px 0 }}
    .metric,.panel {{ background:linear-gradient(145deg,var(--panel2),var(--panel)); border:1px solid var(--line); border-radius:14px }}
    .metric {{ padding:16px }} .metric strong {{ display:block; font:750 27px/1 system-ui,sans-serif; margin-bottom:7px }} .metric span {{ color:var(--muted); font-size:12px; text-transform:uppercase }}
    .controls {{ display:grid; grid-template-columns:1fr 180px 220px; gap:10px; margin:18px 0 }}
    input,select {{ width:100%; color:var(--text); background:#091511; border:1px solid var(--line); border-radius:10px; padding:12px }}
    main {{ display:grid; grid-template-columns:minmax(0,1.4fr) minmax(330px,.8fr); gap:16px }} .panel {{ overflow:hidden }}
    .panel-head {{ padding:16px 18px; border-bottom:1px solid var(--line); display:flex; justify-content:space-between }}
    .queue {{ max-height:72vh; overflow:auto }} .finding {{ width:100%; text-align:left; border:0; border-bottom:1px solid var(--line); color:var(--text); background:transparent; padding:16px 18px; cursor:pointer }}
    .finding:hover,.finding.active {{ background:#173228 }} .finding-top {{ display:flex; gap:9px; align-items:center }} .finding-title {{ font-weight:750; flex:1 }}
    .score {{ color:var(--lime); font-weight:800 }} .target {{ color:var(--cyan); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; margin-top:8px }}
    .pill {{ border:1px solid currentColor; border-radius:999px; padding:2px 7px; font-size:11px; text-transform:uppercase }} .critical,.high {{ color:var(--red) }} .medium {{ color:var(--amber) }} .low,.info {{ color:var(--cyan) }}
    .detail {{ padding:20px; min-height:340px }} .detail h2 {{ font:700 23px/1.2 system-ui,sans-serif }} .detail h3 {{ margin:24px 0 8px; color:var(--lime); font-size:13px; text-transform:uppercase; letter-spacing:.08em }}
    .detail code {{ color:var(--cyan); overflow-wrap:anywhere }} .evidence {{ padding-left:20px }} .copy {{ color:var(--lime); background:transparent; border:1px solid var(--line); border-radius:8px; padding:7px 10px; cursor:pointer }}
    .tabs {{ display:flex; gap:8px; margin:20px 0 12px }} .tab {{ color:var(--muted); background:transparent; border:1px solid var(--line); border-radius:999px; padding:8px 13px; cursor:pointer }} .tab.active {{ color:#05110c; background:var(--lime); border-color:var(--lime) }}
    .secondary {{ margin-top:16px; padding:18px }} table {{ border-collapse:collapse; width:100% }} th,td {{ padding:9px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top }} th {{ color:var(--muted) }}
    .empty {{ padding:30px; color:var(--muted); text-align:center }} footer {{ color:var(--muted); margin:22px 0; font-size:12px }}
    @media (max-width:900px) {{ .shell {{ padding:16px }} header,main {{ display:block }} .notice {{ margin-top:16px }} .metrics {{ grid-template-columns:repeat(3,1fr) }} .controls {{ grid-template-columns:1fr }} .detail {{ min-height:0 }} }}
  </style>
</head>
<body>
<div class="shell">
  <header><div><div class="mark">BARQ // AUTOPILOT</div><h1>{campaign_text}</h1><div class="sub">One workspace. Correlated evidence. A review-ready queue.</div></div><div class="notice">Security hypotheses only. Confirm them manually and only inside written authorization.</div></header>
  <section class="metrics">
    <div class="metric"><strong>{len(findings)}</strong><span>ranked signals</span></div>
    <div class="metric"><strong>{severity_counts['critical'] + severity_counts['high']}</strong><span>high / critical</span></div>
    <div class="metric"><strong>{len(tests)}</strong><span>test plans</span></div>
    <div class="metric"><strong>{len(sequences)}</strong><span>API sequences</span></div>
    <div class="metric"><strong>{len((discovery or {}).get('artifacts', {}))}</strong><span>artifact types</span></div>
    <div class="metric"><strong id="visibleCount">{len(findings)}</strong><span>visible now</span></div>
  </section>
  <div class="tabs"><button class="tab active" data-view="findings">Findings</button><button class="tab" data-view="plans">Test plans</button><button class="tab" data-view="inputs">Inputs</button></div>
  <section id="findingsView">
    <div class="controls"><input id="search" type="search" placeholder="Search title, target, engine, or ID"><select id="severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select><select id="engine"><option value="">All engines</option></select></div>
    <main><section class="panel"><div class="panel-head"><strong>Priority queue</strong><span class="muted">score / 10</span></div><div class="queue" id="queue"></div></section><aside class="panel detail" id="detail"><div class="empty">Select a signal to inspect its evidence and safe next step.</div></aside></main>
  </section>
  <section id="plansView" class="panel secondary" hidden></section>
  <section id="inputsView" class="panel secondary" hidden></section>
  <footer>Generated {escape(generated_at)} · Offline report · No credentials or response headers embedded</footer>
</div>
<script id="barq-data" type="application/json">{_safe_json(payload)}</script>
<script>
const data=JSON.parse(document.getElementById('barq-data').textContent); const queue=document.getElementById('queue'),detail=document.getElementById('detail'); let selected=null;
const esc=v=>String(v??'');
function el(tag,cls,text){{const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=esc(text);return n}}
function renderDetail(f){{detail.replaceChildren();if(!f){{detail.append(el('div','empty','Select a signal to inspect its evidence and safe next step.'));return}} const top=el('div');top.append(el('span','pill '+f.severity,f.severity));top.append(el('h2','',f.title));const target=el('code','',f.target);top.append(target);top.append(el('h3','','Why it matters'));top.append(el('p','',f.evidence.map(x=>x.summary).join(' · ')));top.append(el('h3','','Safe next step'));top.append(el('p','',f.next));top.append(el('h3','','Remediation direction'));top.append(el('p','',f.remediation));top.append(el('h3','','Evidence fingerprints'));const list=el('ul','evidence');f.evidence.forEach(x=>list.append(el('li','',x.kind+' · '+x.fingerprint)));top.append(list);const copy=el('button','copy','Copy review note');copy.onclick=()=>navigator.clipboard?.writeText([f.title,'Target: '+f.target,'Priority: '+f.score+'/10','Next: '+f.next].join('\n'));top.append(copy);detail.append(top)}}
function filtered(){{const q=document.getElementById('search').value.toLowerCase(),sev=document.getElementById('severity').value,eng=document.getElementById('engine').value;return data.findings.filter(f=>(!sev||f.severity===sev)&&(!eng||f.engine===eng)&&(!q||[f.title,f.target,f.engine,f.id].join(' ').toLowerCase().includes(q)))}}
function renderQueue(){{const values=filtered();document.getElementById('visibleCount').textContent=values.length;queue.replaceChildren();if(!values.length)queue.append(el('div','empty','No signals match these filters.'));values.forEach(f=>{{const b=el('button','finding'+(selected===f.id?' active':''));const top=el('div','finding-top');top.append(el('span','pill '+f.severity,f.severity));top.append(el('span','finding-title',f.title));top.append(el('span','score',f.score));b.append(top,el('div','target',f.target));b.onclick=()=>{{selected=f.id;renderQueue();renderDetail(f)}};queue.append(b)}});if(!selected&&values[0]){{selected=values[0].id;renderDetail(values[0])}}}}
const engines=[...new Set(data.findings.map(x=>x.engine))].sort();const engine=document.getElementById('engine');engines.forEach(value=>{{const o=el('option','',value);o.value=value;engine.append(o)}});['search','severity','engine'].forEach(id=>document.getElementById(id).addEventListener('input',renderQueue));
function renderPlans(){{const host=document.getElementById('plansView');host.replaceChildren(el('h2','','Generated test plans ('+data.tests.length+')'));if(!data.tests.length)host.append(el('p','muted','No OpenAPI test plans were discovered.'));data.tests.slice(0,500).forEach((t,i)=>{{const row=el('div','');row.append(el('h3','',(i+1)+'. '+(t.title||t.kind||t.test_type||'Test case')));row.append(el('code','',t.method&&t.path?t.method+' '+t.path:(t.target||JSON.stringify(t).slice(0,220))));if(t.oracle)row.append(el('p','muted','Oracle: '+t.oracle));host.append(row)}})}}
function renderInputs(){{const host=document.getElementById('inputsView');host.replaceChildren(el('h2','','Autodiscovered inputs'));const table=el('table'),head=el('tr');['Type','Count','Files'].forEach(x=>head.append(el('th','',x)));table.append(head);Object.entries(data.discovery.artifacts||{{}}).forEach(([kind,paths])=>{{const row=el('tr');row.append(el('td','',kind),el('td','',paths.length),el('td','',paths.join(', ')));table.append(row)}});host.append(table);if((data.discovery.warnings||[]).length)host.append(el('p','muted',data.discovery.warnings.join(' · ')))}}
document.querySelectorAll('.tab').forEach(tab=>tab.onclick=()=>{{document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x===tab));['findings','plans','inputs'].forEach(name=>document.getElementById(name+'View').hidden=name!==tab.dataset.view);if(tab.dataset.view==='plans')renderPlans();if(tab.dataset.view==='inputs')renderInputs()}});renderQueue();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    main()
