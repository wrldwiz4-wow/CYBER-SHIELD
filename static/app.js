
const $ = s => document.querySelector(s);
function showView(name){
 document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
 document.querySelectorAll('.nav').forEach(n=>n.classList.toggle('active',n.dataset.view===name));
 $('#'+name).classList.add('active');
 const labels={overview:'Dashboard',scanner:'URL Scanner',bulk:'Bulk Scanner',qr:'QR Code Scanner',history:'Scan History',features:'Threat Analysis',reports:'Reports & Export'};
 $('#crumb').textContent=labels[name]||name;
 if(name==='history') loadHistory();
 window.scrollTo(0,0);
}
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>showView(n.dataset.view)));
function setExample(v){$('#urlInput').value=v;showView('scanner')}
async function scanUrl(){
 const input=$('#urlInput').value.trim(), btn=$('#scanBtn'), area=$('#scanResult');
 if(!input){area.innerHTML='<div class="notice">Please enter a URL to scan.</div>';return}
 btn.disabled=true;btn.textContent='Analyzing…';
 area.innerHTML='<div class="panel empty">◌ &nbsp; Inspecting URL structure, DNS, TLS and available threat intelligence…</div>';
 try{
  const res=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:input})});
  const d=await res.json();if(!res.ok)throw new Error(d.error||'Scan failed');
  renderResult(d);
 }catch(e){area.innerHTML=`<div class="notice">${escapeHtml(e.message)}</div>`}
 finally{btn.disabled=false;btn.innerHTML='Scan URL <b>→</b>'}
}
function renderResult(d){
 const cls=d.verdict==='Malicious'?'red-ring':d.verdict==='Suspicious'?'yellow-ring':'green-ring';
 const badge=d.verdict.toLowerCase().replace(' ','-');
 const intel=Object.entries(d.intelligence).map(([k,v])=>`<div class="result-item"><span>${escapeHtml(k)}</span><span>${escapeHtml(v.status)} · ${escapeHtml(v.detail)}</span></div>`).join('');
 const reasons=d.reasons.map(x=>`<li>${escapeHtml(x)}</li>`).join('');
 $('#scanResult').innerHTML=`
 <div class="result-hero"><div class="risk-ring ${cls}">${d.score}</div><div><h2>${escapeHtml(d.verdict)} <span style="color:#8298af;font-size:12px">· Risk score</span></h2><p>${escapeHtml(d.url)}</p><small style="color:#71869e">Scanned ${escapeHtml(d.scanned_at)}</small></div><span class="badge ${badge}">${escapeHtml(d.verdict)}</span></div>
 <div class="result-grid">
 <article class="result-card"><h4>⌁ &nbsp; URL indicators</h4><ul class="reason-list">${reasons}</ul></article>
 <article class="result-card"><h4>◈ &nbsp; Domain & connection</h4>
 <div class="result-item"><span>Domain</span><span>${escapeHtml(d.domain)}</span></div>
 <div class="result-item"><span>HTTPS</span><span>${d.https?'Yes':'No'}</span></div>
 <div class="result-item"><span>SSL / TLS</span><span>${escapeHtml(d.ssl.status)} · ${escapeHtml(d.ssl.detail)}</span></div>
 <div class="result-item"><span>DNS addresses</span><span>${escapeHtml((d.dns||[]).join(', ')||'Not available')}</span></div>
 <div class="result-item"><span>Domain age</span><span>${escapeHtml(d.domain_age.detail)}</span></div></article>
 <article class="result-card"><h4>◎ &nbsp; Threat intelligence</h4>${intel}</article>
 <article class="result-card"><h4>⇩ &nbsp; Next steps</h4><p style="font-size:11px">Do not enter passwords or payment details on an unfamiliar site. Verify the domain through an independent trusted source. A clean result cannot guarantee safety.</p></article>
 </div><div class="disclaimer">ⓘ ${escapeHtml(d.disclaimer)}</div>`;
}
function escapeHtml(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function bulkScan(){
 const f=$('#bulkFile').files[0];if(!f){$('#bulkResults').innerHTML='<div class="notice">Choose a CSV or TXT file first.</div>';return}
 const fd=new FormData();fd.append('file',f);$('#bulkResults').textContent='Scanning URLs…';
 try{const r=await fetch('/api/bulk',{method:'POST',body:fd}),d=await r.json();if(!r.ok)throw Error(d.error);
 $('#bulkResults').innerHTML=`<h3>${d.results.length} results</h3><div class="table-wrap"><table><thead><tr><th>URL</th><th>RISK SCORE</th><th>VERDICT</th></tr></thead><tbody>${d.results.map(x=>`<tr><td>${escapeHtml(x.url)}</td><td>${x.score}/100</td><td><span class="badge ${x.verdict.toLowerCase().replace(' ','-')}">${escapeHtml(x.verdict)}</span></td></tr>`).join('')}</tbody></table></div>`;
 }catch(e){$('#bulkResults').innerHTML=`<div class="notice">${escapeHtml(e.message)}</div>`}
}
async function loadHistory(){
 const r=await fetch('/api/history'),rows=await r.json();
 window.historyRows=rows;drawHistory(rows);
}
function drawHistory(rows){
 $('#historyTable').innerHTML=`<table><thead><tr><th>URL / DOMAIN</th><th>SCORE</th><th>VERDICT</th><th>DATE</th><th>REPORT</th></tr></thead><tbody>${rows.length?rows.map(x=>`<tr><td><b>${escapeHtml(x.domain)}</b><small>${escapeHtml(x.url)}</small></td><td>${x.score}/100</td><td><span class="badge ${x.verdict.toLowerCase().replace(' ','-')}">${escapeHtml(x.verdict)}</span></td><td>${escapeHtml(x.scanned_at)}</td><td><a class="text-btn" href="/report/${x.id}">PDF ↓</a></td></tr>`).join(''):'<tr><td colspan="5" class="empty">No scan records found.</td></tr>'}</tbody></table>`;
}
function filterHistory(){const q=$('#historySearch').value.toLowerCase();drawHistory((window.historyRows||[]).filter(x=>x.domain.toLowerCase().includes(q)||x.url.toLowerCase().includes(q)))}
function decodeQR(){
 const f=$('#qrFile').files[0];if(!f){$('#qrOutput').textContent='Choose an image first.';return}
 if(!window.jsQR){$('#qrOutput').textContent='QR decoder library could not load. Check your internet connection.';return}
 const img=new Image(),url=URL.createObjectURL(f);
 img.onload=()=>{const c=document.createElement('canvas'),ctx=c.getContext('2d');c.width=img.naturalWidth;c.height=img.naturalHeight;ctx.drawImage(img,0,0);const data=ctx.getImageData(0,0,c.width,c.height);const code=jsQR(data.data,data.width,data.height);URL.revokeObjectURL(url);
 if(code){$('#qrOutput').innerHTML=`<div class="result-card"><b>QR content found</b><p style="margin:8px 0;word-break:break-all">${escapeHtml(code.data)}</p><button class="primary" id="scanQr">Scan extracted URL →</button></div>`;$('#scanQr').onclick=()=>{showView('scanner');$('#urlInput').value=code.data;scanUrl()}}
 else $('#qrOutput').textContent='No QR code was detected in this image.'};
 img.onerror=()=>$('#qrOutput').textContent='Could not read this image.';img.src=url;
}
const activityCtx=document.getElementById('activityChart');
if(activityCtx)new Chart(activityCtx,{type:'line',data:{labels:['Mon','Tue','Wed','Thu','Fri','Sat','Sun'],datasets:[{label:'Scans',data:[2,4,3,6,4,8,5],borderColor:'#38aaff',backgroundColor:'rgba(56,170,255,.12)',fill:true,tension:.4,pointRadius:3}]},options:{plugins:{legend:{display:false}},scales:{x:{grid:{color:'#1d3044'},ticks:{color:'#748aa2'}},y:{beginAtZero:true,grid:{color:'#1d3044'},ticks:{color:'#748aa2',precision:0}}}}});
const riskCtx=document.getElementById('riskChart');
if(riskCtx)new Chart(riskCtx,{type:'doughnut',data:{labels:['Low risk','Suspicious','Malicious'],datasets:[{data:[Number('{{ safe }}'),Number('{{ suspicious }}'),Number('{{ malicious }}')],backgroundColor:['#2dd4a0','#f4bd4f','#ff5d70'],borderWidth:0,hoverOffset:4}]},options:{cutout:'76%',plugins:{legend:{display:false}}}});
