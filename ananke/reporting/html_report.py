"""HTML rendering of the assessment report.

Same inputs as the markdown renderer: committed aggregates only, never the raw
store. The renderer cannot leak what it cannot read.

Three rules, in priority order:

1. **Every dynamic value is escaped at the point of interpolation.** Aggregates
   are validated upstream (sector labels are shape-checked, the guard walks the
   payload), but this renderer does not rely on that: defense in depth means
   the XSS fix survives a future counter that forgets its input discipline.
2. **The rendered document passes the disclosure guard before it is written**,
   exactly as the markdown output does. Two formats, one gate.
3. **No network.** One file, inline CSS and SVG, `color-scheme: light dark`
   with a designed dark palette, print forces light. A report opened inside a
   regulated buyer's network must not emit a request on open.

The chart embeds validity *periods* as date pairs, no identity - the same
discipline the aggregate itself follows.
"""

from __future__ import annotations

import datetime as dt
import html
import json


def esc(value: object) -> str:
    """Escape one value for HTML text or attribute context."""
    return html.escape(str(value), quote=True)


def _counter_rows(counter: dict, total: int) -> str:
    rows = []
    for key, n in sorted(counter.items(), key=lambda kv: -kv[1]):
        pct = f"{100 * n / total:.0f}%" if total else "n/a"
        rows.append(f"<tr><td>{esc(key)}</td><td class='n'>{n}</td>"
                    f"<td class='n'>{esc(pct)}</td></tr>")
    return "".join(rows)


def _decision_split(agg: dict) -> tuple[int, int]:
    return agg.get("self_resolving_via_rotation", 0), agg.get("intervention_required", 0)


def render_html(sectors_payload: dict, scores_payload: dict | None,
                validity_pairs: list[dict] | None = None) -> str:
    """Render the full report page from aggregate payloads.

    `validity_pairs` is an optional list of {"nb": iso, "na": iso} date pairs
    for the horizon chart. It carries no identity and must not: the caller is
    responsible for supplying dates only, and the guard checks the result
    anyway.
    """
    milestone = (sectors_payload.get("milestone") or {}).get("date", "2030-12-31")
    ms_year = int(milestone[:4])
    generated = esc(sectors_payload.get("generated_at", "")[:10])
    provenance = esc(sectors_payload.get("provenance", "measured"))
    modality = esc(sectors_payload.get("modality", ""))
    policy = sectors_payload.get("disclosure_policy", {})
    first_party = bool(policy.get("first_party_estate"))

    sections = []
    for sector, agg in sorted(sectors_payload.get("sectors", {}).items()):
        n = agg.get("hosts_with_certificate", 0)
        resolve, intervene = _decision_split(agg)
        stats = agg.get("rotation_stats") or {}
        beyond = agg.get("valid_beyond_milestone",
                         agg.get("valid_beyond_2030_milestone", {}))
        expiry_rows = "".join(
            f"<tr><td>{esc(y)}</td><td class='n'>{c}</td></tr>"
            for y, c in sorted(agg.get("intervention_expiry_years", {}).items()))
        sections.append(f"""
<h2><span class="num">sector — {esc(sector)}</span>The split a plan is built from</h2>
<div class="split">
  <div class="cell g">
    <div><span class="big">{resolve}</span><span class="pct">{esc(f"{100*resolve/n:.0f}%" if n else "n/a")}</span></div>
    <h3>Self-resolving through rotation <span class="chip">measured</span></h3>
    <p>Expires on or before {esc(milestone)}. Normal renewal replaces it; the
    only action required is that issuance policy has changed by then.</p>
  </div>
  <div class="cell r">
    <div><span class="big">{intervene}</span><span class="pct">{esc(f"{100*intervene/n:.0f}%" if n else "n/a")}</span></div>
    <h3>Intervention required <span class="chip">measured</span></h3>
    <p>Still valid after the milestone. No renewal is scheduled that would
    replace it; each one is a deliberate change.</p>
  </div>
</div>

<table class="bands"><thead><tr><th>Rotation band</th><th>Hosts</th><th>Share</th></tr></thead>
<tbody>{_counter_rows(agg.get("rotation_bands", {}), n)}</tbody></table>

<div class="split" style="margin-top:20px">
  <div class="cell">
    <div><span class="big">{esc(stats.get("rotations_before_milestone", "?"))}</span><span class="pct">×</span></div>
    <h3>Rotations before the milestone <span class="chip">measured</span></h3>
    <p>At the median validity of {esc(stats.get("median", "?"))} days. An estate
    that rotates once has one attempt.</p>
  </div>
  <div class="cell">
    <div><span class="big">{esc(str(stats.get("max", "?")))}</span><span class="pct">days</span></div>
    <h3>Longest validity in the estate <span class="chip">measured</span></h3>
    <p>Certificates beyond the milestone: {beyond.get("True", 0)} of {n}.</p>
  </div>
</div>

{f'<table class="bands"><thead><tr><th>Intervention class expires</th><th>Hosts</th></tr></thead><tbody>{expiry_rows}</tbody></table>' if expiry_rows else ''}

<h3 class="sub-h">Issuer relationships <span class="chip">measured</span></h3>
<p class="lede">How many CA relationships must change for issuance policy to change.</p>
<table class="bands"><thead><tr><th>Issuer</th><th>Certs</th><th>Share</th></tr></thead>
<tbody>{_counter_rows(agg.get("issuers", {}), n)}</tbody></table>
""")

    chart = ""
    if validity_pairs:
        safe_pairs = [{"nb": esc(p["nb"])[:10], "na": esc(p["na"])[:10]}
                      for p in validity_pairs if "nb" in p and "na" in p]
        chart = f"""
<h2><span class="num">horizon</span>Every certificate as a segment in time</h2>
<p class="lede">One row per certificate, issuance to expiry. The rule is the
milestone; move it to see how the estate responds to a different deadline.</p>
<div class="controls">
  <label for="ms">Milestone</label>
  <input type="range" id="ms" min="{ms_year - 2}" max="{ms_year + 6}" step="1" value="{ms_year}">
  <output id="ms-out">31 Dec {ms_year}</output>
</div>
<figure><svg id="horizon" viewBox="0 0 900 430" role="img"
  aria-label="Certificate validity periods against a movable milestone">
  <g id="grid"></g><g id="segs"></g><g id="rule"></g></svg>
<figcaption>Segments carry no identity: dates only, the same discipline the
aggregate follows.</figcaption></figure>
<script>
const CERTS={json.dumps(safe_pairs, separators=(",", ":"))};
const MS_DEFAULT={ms_year};
{_CHART_JS}
</script>"""

    limits = """
<h2><span class="num">limits</span>What this assessment does not tell you</h2>
<ul class="limits">
  <li><strong>Whether these hosts can negotiate a hybrid key exchange at all.</strong>
  That needs a software inventory export. Until provided, the replacement plan
  cannot be costed.</li>
  <li><strong>Whether the supplied estate is complete.</strong> Fields are
  measured; completeness of the set is <span class="chip">reported</span>.</li>
  <li>Cryptography at rest, HSMs, internal PKI, pinned certificates.</li>
  <li>A certificate using RSA says nothing about the negotiated key exchange.
  Different layers.</li>
</ul>"""

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PQC Crypto-Agility Assessment</title>
<style>{_CSS}</style></head><body><div class="sheet">
<header>
  <div class="eyebrow">ANANKE · generated {generated} · modality {modality} · provenance {provenance}</div>
  <h1>Crypto-agility assessment</h1>
  <p class="sub">Aggregates only; host-level data was not read by this renderer.
  Milestone: {esc(milestone)}{" · first-party estate" if first_party else ""}.</p>
</header>
{"".join(sections)}
{chart}
{limits}
<footer><span>counts and dates only, by construction</span>
<span>milestone {esc(milestone)}</span></footer>
</div></body></html>"""


_CSS = """
:root{color-scheme:light dark;
 --ground:#E7EBEE;--surface:#FDFDFC;--ink:#141D26;--muted:#5D6E7C;
 --rule:#C3CBD2;--hair:#D8DEE3;--inset:#F4F6F8;
 --intervene:#9E2B25;--resolve:#2E6B5E;--intervene-soft:#9E2B2514;
 --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
 --serif:"Iowan Old Style",Palatino,Georgia,serif;
 --sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
@media (prefers-color-scheme:dark){:root{
 --ground:#0E1216;--surface:#161B21;--ink:#E9EEF2;--muted:#94A3AF;
 --rule:#37424C;--hair:#242D36;--inset:#1B222A;
 --intervene:#E8735F;--resolve:#57C4A3;--intervene-soft:#E8735F1A}}
*{box-sizing:border-box}
body{margin:0;background:var(--ground);color:var(--ink);font-family:var(--sans);
 font-size:15px;line-height:1.55}
.sheet{max-width:960px;margin:0 auto;background:var(--surface);
 border-left:1px solid var(--hair);border-right:1px solid var(--hair);
 padding:0 clamp(20px,5vw,64px) 72px}
header{padding:48px 0 28px;border-bottom:2px solid var(--ink)}
.eyebrow{font-family:var(--mono);font-size:11px;letter-spacing:.16em;
 text-transform:uppercase;color:var(--muted)}
h1{font-family:var(--serif);font-weight:400;font-size:clamp(28px,4.4vw,42px);
 line-height:1.12;margin:14px 0 10px}
.sub{color:var(--muted);max-width:62ch;margin:0}
h2{font-family:var(--serif);font-weight:400;font-size:clamp(21px,2.8vw,27px);
 margin:56px 0 6px}
h2 .num{font-family:var(--mono);font-size:12px;color:var(--muted);display:block;
 letter-spacing:.14em;margin-bottom:6px;text-transform:uppercase}
.sub-h{font-size:15px;margin:34px 0 2px}
.lede{color:var(--muted);max-width:64ch;margin:0 0 18px}
.chip{font-family:var(--mono);font-size:10px;letter-spacing:.08em;
 text-transform:uppercase;border:1px solid var(--rule);border-radius:2px;
 padding:2px 6px;color:var(--muted);white-space:nowrap;vertical-align:2px}
.split{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));
 gap:1px;background:var(--hair);border:1px solid var(--hair);margin:8px 0 0}
.cell{background:var(--surface);padding:22px 20px}
.cell .big{font-family:var(--serif);font-size:52px;line-height:1}
.cell .pct{font-family:var(--mono);font-size:13px;color:var(--muted);margin-left:8px}
.cell h3{font-size:14px;margin:12px 0 6px;font-weight:600}
.cell p{margin:0;font-size:13.5px;color:var(--muted)}
.cell.r{border-top:3px solid var(--intervene)}.cell.r .big{color:var(--intervene)}
.cell.g{border-top:3px solid var(--resolve)}.cell.g .big{color:var(--resolve)}
.controls{display:flex;flex-wrap:wrap;gap:14px;align-items:center;
 border:1px solid var(--hair);background:var(--inset);padding:14px 16px;margin:0 0 18px}
.controls label{font-family:var(--mono);font-size:11px;letter-spacing:.1em;
 text-transform:uppercase;color:var(--muted)}
input[type=range]{flex:1;min-width:180px;accent-color:var(--ink)}
output{font-family:var(--mono);font-size:15px}
figure{margin:0}svg{display:block;width:100%;height:auto}
figcaption{font-size:12.5px;color:var(--muted);margin-top:10px}
.bands{border-collapse:collapse;width:100%;margin-top:6px;font-size:14px}
.bands th,.bands td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--hair)}
.bands th{font-family:var(--mono);font-size:10.5px;letter-spacing:.1em;
 text-transform:uppercase;color:var(--muted);font-weight:400}
.bands td.n{text-align:right;font-family:var(--mono)}
ul.limits{padding-left:18px;color:var(--muted);max-width:68ch}
ul.limits li{margin:7px 0}ul.limits strong{color:var(--ink)}
footer{margin-top:60px;padding-top:18px;border-top:1px solid var(--hair);
 font-family:var(--mono);font-size:11px;color:var(--muted);
 display:flex;flex-wrap:wrap;gap:18px;justify-content:space-between}
:focus-visible{outline:2px solid var(--intervene);outline-offset:2px}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
@media print{:root{color-scheme:light}body{background:#fff}
 .sheet{border:0}.controls{display:none}}
"""

_CHART_JS = """
const pd=s=>Date.parse(s);
const T0=Math.min(...CERTS.map(c=>pd(c.nb)))-90*864e5;
const T1=Math.max(...CERTS.map(c=>pd(c.na)))+180*864e5;
const W=900,H=430,L=8,R=16,TOP=26,BOT=30;
const x=t=>L+(t-T0)/(T1-T0)*(W-L-R);
const ms=document.getElementById('ms'),out=document.getElementById('ms-out');
const NS='http://www.w3.org/2000/svg';
const el=(n,a)=>{const e=document.createElementNS(NS,n);
 for(const k in a)e.setAttribute(k,a[k]);return e;};
function grid(){const g=document.getElementById('grid');g.textContent='';
 const y0=new Date(T0).getUTCFullYear(),y1=new Date(T1).getUTCFullYear();
 for(let y=y0;y<=y1;y++){const px=x(Date.UTC(y,0,1));
  if(px<L||px>W-R)continue;
  g.appendChild(el('line',{x1:px,y1:TOP-8,x2:px,y2:H-BOT,stroke:'var(--hair)'}));
  const t=el('text',{x:px+4,y:H-BOT+16,fill:'var(--muted)','font-size':11,
   'font-family':'var(--mono)'});t.textContent=y;g.appendChild(t);}}
function draw(){const year=+ms.value,M=Date.UTC(year,11,31);
 out.textContent='31 Dec '+year;
 const segs=document.getElementById('segs');segs.textContent='';
 const sorted=[...CERTS].sort((a,b)=>pd(a.na)-pd(b.na));
 const rowH=(H-TOP-BOT)/sorted.length;
 sorted.forEach((c,i)=>{const a=pd(c.nb),b=pd(c.na),cross=b>M;
  segs.appendChild(el('rect',{x:x(a),y:TOP+i*rowH+1,
   width:Math.max(2,x(b)-x(a)),height:Math.max(2,rowH-2.5),
   fill:cross?'var(--intervene)':'var(--resolve)',opacity:cross?0.92:0.5,rx:1}));});
 const px=x(M),r=document.getElementById('rule');r.textContent='';
 r.appendChild(el('rect',{x:px,y:TOP-10,width:Math.max(1,x(T1)-px),
  height:H-TOP-BOT+10,fill:'var(--intervene-soft)'}));
 r.appendChild(el('line',{x1:px,y1:TOP-12,x2:px,y2:H-BOT+2,stroke:'var(--ink)',
  'stroke-width':1.5,'stroke-dasharray':'5 3'}));
 const lab=el('text',{x:px+6,y:TOP-16,fill:'var(--ink)','font-size':11,
  'font-family':'var(--mono)','font-weight':600});
 lab.textContent='milestone '+year;r.appendChild(lab);}
grid();draw();ms.addEventListener('input',draw);
"""
