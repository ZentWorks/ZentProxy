const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const arr = (v) => Array.isArray(v) ? v : [];
const obj = (v) => v && typeof v === 'object' && !Array.isArray(v) ? v : {};
const num = (v) => Number.isFinite(Number(v)) ? Number(v) : 0;
const tr = (s) => window.ZentI18n ? ZentI18n.t(s) : s;
const localize = (root=document) => window.ZentI18n && ZentI18n.apply(root);
const pageIcons = { dashboard:'overview', hosts:'proxy-hosts', certificates:'certificates', routing:'routing', access:'access', analytics:'analytics', providers:'trusted-proxies', zentloop:'zentloop', migration:'migration', developers:'developer', documentation:'documentation', audit:'audit' };
function icon(name, cls='') { return `<svg class="ui-icon ${esc(cls)}" aria-hidden="true"><use href="/icons.svg#${esc(name)}"></use></svg>`; }
function metric(iconName, label, value) { return `<div class="card metric metric-with-icon"><span class="metric-icon">${icon(iconName)}</span><div class="metric-copy"><div class="label">${label}</div><div class="value">${value}</div></div></div>`; }
function sectionHeading(iconName, title, extra='') { return `<div class="section-head"><h2 class="section-title"><span class="section-icon">${icon(iconName)}</span>${title}</h2>${extra}</div>`; }
function emptyState(iconName, text) { return `<div class="empty empty-with-icon"><span class="empty-icon">${icon(iconName)}</span><span>${text}</span></div>`; }

function applyAutocompletePolicy(root = document) {
  const fields = [];
  if (root?.matches?.('form, input, textarea')) fields.push(root);
  if (root?.querySelectorAll) fields.push(...root.querySelectorAll('form, input, textarea'));

  for (const el of fields) {
    if (el.closest?.('#login-form') || el.id === 'login-form') continue;
    if (el.tagName === 'FORM') {
      el.setAttribute('autocomplete', 'off');
      continue;
    }
    if (el.tagName === 'TEXTAREA') {
      el.setAttribute('autocomplete', 'off');
      continue;
    }
    const type = (el.getAttribute('type') || 'text').toLowerCase();
    if (['text', 'search', 'email', 'url', 'tel', 'number', 'password'].includes(type)) {
      el.setAttribute('autocomplete', 'off');
    }
  }
}

applyAutocompletePolicy();
new MutationObserver((mutations) => {
  for (const mutation of mutations) {
    for (const node of mutation.addedNodes) {
      if (node.nodeType === Node.ELEMENT_NODE) applyAutocompletePolicy(node);
    }
  }
}).observe(document.body, { childList: true, subtree: true });

const state = {
  csrf: '', me: null, providers: [], hosts: [], page: 'dashboard', poll: null,
  migrationCreds: null, migrationImporting: false, certificates: [], accessLists: [], docsArticle: 'getting-started', hostDomains: [], hostSearch: '', hostView: 'list', collapsedHostGroups: new Set(), analyticsAuto: true, analyticsRange: '24h', analyticsHost: '', analyticsCountdown: 5,
};

const titles = {
  dashboard: ['Overview', 'Traffic, health and the things that matter.'],
  hosts: ['Proxy Hosts', 'Domains and upstreams without config-file archaeology.'],
  certificates: ['Certificates', "Let's Encrypt, automatic renewal and imported certificates."],
  routing: ['Routing', 'Redirects, 404 hosts and TCP/UDP streams.'],
  access: ['Access Lists', 'Reusable IP rules and authentication policies for proxy hosts.'],
  analytics: ['Analytics', 'Per-host traffic down to paths and client IPs.'],
  providers: ['Trusted Proxies', 'Real client IP handling with built-in and custom trusted proxy providers.'],
  zentloop: ['ZentLoop', 'Route unmatched hosts into the deception backend.'],
  migration: ['Migration', 'Analyze first, then move the full supported configuration into ZentProxy.'],
  developers: ['Developer API', 'Scoped API keys and a stable versioned interface.'],
  audit: ['Audit Log', 'Who changed what and when.'],
  documentation: ['Documentation', 'Search and read the ZentProxy documentation without leaving the WebUI.'],
};

async function api(path, opt = {}) {
  opt.headers = { ...(opt.headers || {}), Accept: 'application/json' };
  if (opt.body && !opt.headers['Content-Type']) opt.headers['Content-Type'] = 'application/json';
  if (state.csrf && opt.method && !['GET', 'HEAD'].includes(opt.method)) opt.headers['X-ZentProxy-CSRF'] = state.csrf;
  const r = await fetch(path, opt);
  let data = null;
  const ct = r.headers.get('content-type') || '';
  if (ct.includes('json')) data = await r.json(); else data = await r.text();
  if (r.status === 401) {
    showLogin();
    throw new Error('Authentication required');
  }
  if (!r.ok) throw new Error(data?.error || `HTTP ${r.status}`);
  return data;
}

function fmtNum(n) { return new Intl.NumberFormat().format(num(n)); }
function fmtBytes(n) {
  n = num(n);
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}
function esc(v) {
  return String(v ?? '').replace(/[&<>'"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c]));
}
function toast(msg) {
  const e = $('#toast');
  e.textContent = msg;
  e.classList.remove('hidden');
  setTimeout(() => e.classList.add('hidden'), 2600);
}
function showLogin() {
  clearInterval(state.poll);
  $('#app').classList.add('hidden');
  $('#login').classList.remove('hidden');
}
function showApp() {
  $('#login').classList.add('hidden');
  $('#app').classList.remove('hidden');
}

async function init() {
  try {
    const me = await api('/api/v1/auth/me');
    state.me = me;
    state.csrf = me.csrf_token;
    if (me.language && window.ZentI18n) ZentI18n.setLanguage(me.language);
    showApp();
    await loadPage('dashboard');
  } catch {
    showLogin();
  }
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#login-error').textContent = '';
  try {
    const d = await api('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username: $('#login-user').value, password: $('#login-pass').value }),
    });
    state.csrf = d.csrf_token;
    state.me = d;
    if (d.language && window.ZentI18n) ZentI18n.setLanguage(d.language);
    showApp();
    await loadPage('dashboard');
  } catch (err) {
    $('#login-error').textContent = err.message;
  }
});

$('#logout').addEventListener('click', async () => {
  try { await api('/api/v1/auth/logout', { method: 'POST' }); } catch {}
  state.csrf = '';
  state.migrationCreds = null;
  showLogin();
});

$('.sidebar').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-page]');
  if (b) loadPage(b.dataset.page);
});

async function loadPage(page) {
  clearInterval(state.poll);
  if (page !== 'migration') state.migrationCreds = null;
  state.page = page;
  $$('.sidebar button[data-page]').forEach((b) => b.classList.toggle('active', b.dataset.page === page));
  $('#page-title').textContent = tr(titles[page][0]);
  $('#page-subtitle').textContent = tr(titles[page][1]);
  const pageIcon = pageIcons[page] || 'overview';
  $('#page-icon').innerHTML = `<svg aria-hidden="true"><use href="/icons.svg#${pageIcon}"></use></svg>`;
  $('#top-actions').innerHTML = '';
  $('#content').innerHTML = '<div class="muted">Loading…</div>';
  try {
    if (page === 'dashboard') await dashboard();
    if (page === 'hosts') await hosts();
    if (page === 'certificates') await certificatesPage();
    if (page === 'routing') await routingPage();
    if (page === 'access') await accessListsPage();
    if (page === 'analytics') await analytics();
    if (page === 'providers') await providers();
    if (page === 'zentloop') await zentloop();
    if (page === 'migration') await migrationPage();
    if (page === 'developers') await developers();
    if (page === 'audit') await audit();
    if (page === 'documentation') await documentationPage();
    localize(document);
  } catch (e) {
    $('#content').innerHTML = `<div class="card danger-text">${esc(e.message)}</div>`;
  }
}

async function dashboard() {
  const [infoRaw, statsRaw] = await Promise.all([
    api('/api/v1/system/info'), api('/api/v1/stats/summary?range=24h'),
  ]);
  const info = obj(infoRaw), stats = obj(statsRaw);
  const version = String(info.version || '').trim();
  $('#version').textContent = version && version.toLowerCase() !== 'dev' ? `${version} · API v1` : 'API v1';
  $('#content').innerHTML = `
    <div class="cards">
      ${metric('proxy-hosts', 'Proxy hosts', `${fmtNum(info.enabled_hosts)}<span class="muted"> / ${fmtNum(info.hosts)}</span>`)}
      ${metric('requests', 'Requests · 24h', fmtNum(stats.requests))}
      ${metric('clients', 'Unique IPs · 24h', fmtNum(stats.unique_ips))}
      ${metric('traffic', 'Traffic · 24h', fmtBytes(stats.bytes))}
    </div>
    <div class="grid-2">
      <div class="card">${sectionHeading('proxy-hosts', 'Top hosts', '<span class="pill">24h</span>')}${countList(arr(stats.top_hosts))}</div>
      <div class="card">${sectionHeading('status', 'Status codes', `<span class="pill">Avg ${num(stats.average_time_ms).toFixed(1)} ms</span>`)}${statusBars(obj(stats.status_classes), num(stats.requests))}</div>
    </div>
    <div class="grid-2">
      <div class="card">${sectionHeading('paths', 'Top paths')}${countList(arr(stats.top_paths))}</div>
      <div class="card">${sectionHeading('ip', 'Top client IPs')}${countList(arr(stats.top_ips))}</div>
    </div>`;
}

function countList(items) {
  items = arr(items);
  if (!items.length) return emptyState('analytics', 'No traffic yet.');
  return `<div class="list">${items.map((i) => `<div class="list-row"><span class="code">${esc(i.key)}</span><strong>${fmtNum(i.count)}</strong></div>`).join('')}</div>`;
}
function domainCountList(items) {
  items = arr(items);
  if (!items.length) return emptyState('analytics', 'No traffic yet.');
  return `<div class="list">${items.map((i) => `<button type="button" class="list-row analytics-domain-row" data-analytics-domain="${esc(i.key)}"><span class="code">${esc(i.key)}</span><strong>${fmtNum(i.count)}</strong></button>`).join('')}</div>`;
}
function statusBars(s, total) {
  s = obj(s); total = num(total);
  return ['2xx', '3xx', '4xx', '5xx'].map((k) => {
    const n = num(s[k]), p = total ? Math.round(n / total * 100) : 0;
    return `<div class="list-row"><div class="grow"><div>${k} <span class="muted">${p}%</span></div><progress class="status-progress" value="${n}" max="${total || 1}"></progress></div><strong>${fmtNum(n)}</strong></div>`;
  }).join('');
}

async function loadProviders() {
  state.providers = arr(await api('/api/v1/trusted-proxy-providers'));
  return state.providers;
}

async function loadCertificates() {
  state.certificates = arr(await api('/api/v1/certificates'));
  return state.certificates;
}
async function loadAccessLists() {
  state.accessLists = arr(await api('/api/v1/access-lists'));
  return state.accessLists;
}

const commonCountrySecondLevels = new Set(['ac','asn','co','com','edu','firm','gen','go','gov','id','ind','ltd','me','mil','net','ne','nom','or','org','plc','sch']);
function normalizeHostDomain(domain) {
  let d=String(domain||'').trim().toLowerCase().replace(/^\*\./,'').replace(/\.$/,'');
  if(d.startsWith('[')&&d.endsWith(']')) d=d.slice(1,-1);
  return d;
}
function isIPAddress(value) {
  const v=normalizeHostDomain(value);
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(v) || v.includes(':');
}
function registrableDomain(domain) {
  const d=normalizeHostDomain(domain);
  if(!d || isIPAddress(d)) return '';
  const parts=d.split('.').filter(Boolean);
  if(parts.length<2) return d;
  const tld=parts.at(-1), sld=parts.at(-2);
  if(tld.length===2 && commonCountrySecondLevels.has(sld) && parts.length>=3) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}
function hostGroup(h) {
  const domains=arr(h.domains).map(normalizeHostDomain).filter(Boolean);
  const domain=domains.find(d=>!isIPAddress(d));
  if(domain) return registrableDomain(domain) || domain;
  if(domains.some(isIPAddress)) return '__ip__';
  return '__other__';
}
function hostMatches(h, query) {
  const q=String(query||'').trim().toLowerCase();
  if(!q) return true;
  const target=`${h.scheme||''}://${h.forward_host||''}:${h.forward_port||''}`;
  const hay=[h.name, h.forward_host, h.forward_port, target, ...arr(h.domains)].join(' ').toLowerCase();
  return hay.includes(q);
}
function hostRow(h) {
  return `<tr data-host="${h.id}" class="clickable-row"><td><span class="status-dot ${h.enabled ? 'ok' : 'off'}" title="${h.enabled ? 'Online' : 'Disabled'}" aria-label="${h.enabled ? 'Online' : 'Disabled'}"></span></td><td><strong>${esc(h.name)}</strong></td><td>${arr(h.domains).map((d) => `<span class="pill">${esc(d)}</span>`).join(' ')}</td><td class="code">${esc(h.scheme)}://${esc(h.forward_host)}:${num(h.forward_port)}</td><td>${h.certificate_id ? `<span class="pill good">${esc(certificateName(h.certificate_id))}</span>` : '<span class="pill">HTTP</span>'}</td><td>${h.statistics_enabled ? '<span class="pill good">On</span>' : '<span class="pill">Off</span>'}</td><td>${esc(providerName(h.trusted_proxy_provider_id))}</td><td>${esc(accessListName(h.access_list_id))}</td><td class="row-chevron">›</td></tr>`;
}
function hostTable(hs) {
  return `<div class="table-wrap"><table><thead><tr><th>Status</th><th>Name</th><th>Domains</th><th>Upstream</th><th>TLS</th><th>Analytics</th><th>Trusted proxy</th><th>Access</th><th class="row-action-col"></th></tr></thead><tbody>${hs.map(hostRow).join('')}</tbody></table></div>`;
}
function renderHostsContent() {
  const filtered=state.hosts.filter(h=>hostMatches(h,state.hostSearch));
  if(!filtered.length) {
    $('#content').innerHTML=emptyState('search', state.hostSearch ? 'No proxy hosts match your search.' : 'No proxy hosts yet. Add the first one or use Migration.');
    return;
  }
  if(state.hostView!=='grouped') {
    $('#content').innerHTML=hostTable(filtered);
  } else {
    const groups=new Map();
    [...filtered].sort((a,b)=>String(a.name||'').localeCompare(String(b.name||''),undefined,{sensitivity:'base'})).forEach(h=>{
      const key=hostGroup(h); if(!groups.has(key)) groups.set(key,[]); groups.get(key).push(h);
    });
    const keys=[...groups.keys()].sort((a,b)=>{
      if(a==='__ip__') return 1; if(b==='__ip__') return -1;
      if(a==='__other__') return 1; if(b==='__other__') return -1;
      return a.localeCompare(b,undefined,{sensitivity:'base'});
    });
    $('#content').innerHTML=`<div class="host-groups">${keys.map(key=>{
      const items=groups.get(key), collapsed=state.collapsedHostGroups.has(key);
      const label=key==='__ip__'?'IP addresses':key==='__other__'?'Other':key;
      return `<section class="card host-group"><button class="host-group-head" type="button" data-host-group="${esc(key)}" aria-expanded="${collapsed?'false':'true'}"><span><span class="host-group-chevron">${collapsed?'›':'⌄'}</span><strong>${esc(label)}</strong></span><span class="muted">${fmtNum(items.length)}</span></button><div class="host-group-body ${collapsed?'hidden':''}">${hostTable(items)}</div></section>`;
    }).join('')}</div>`;
    $$('[data-host-group]').forEach(b=>b.onclick=()=>{const key=b.dataset.hostGroup;if(state.collapsedHostGroups.has(key))state.collapsedHostGroups.delete(key);else state.collapsedHostGroups.add(key);renderHostsContent();wireHostRows();});
  }
  wireHostRows();
}
function wireHostRows(){ $$('[data-host]').forEach((r)=>r.onclick=()=>openHost(state.hosts.find((h)=>h.id===+r.dataset.host))); }
async function persistHostView(view){
  if(!['list','grouped'].includes(view)) return;
  state.hostView=view;
  if(state.me) state.me.proxy_hosts_view=view;
  renderHostsContent();
  try { await api('/api/v1/user/preferences/proxy-hosts-view',{method:'PUT',body:JSON.stringify({view})}); } catch(e){ toast(e.message); }
}
async function hosts() {
  const [hsRaw] = await Promise.all([api('/api/v1/hosts'), loadProviders(), loadCertificates(), loadAccessLists()]);
  state.hosts = arr(hsRaw);
  state.hostView = state.me?.proxy_hosts_view === 'grouped' ? 'grouped' : 'list';
  $('#top-actions').innerHTML = `<div class="host-toolbar"><label class="host-search">${icon('search')}<input id="host-search" type="search" placeholder="Search name, domain or target…" value="${esc(state.hostSearch)}"></label><select id="host-view" aria-label="View"><option value="list" ${state.hostView==='list'?'selected':''}>List</option><option value="grouped" ${state.hostView==='grouped'?'selected':''}>Grouped by domain</option></select><button id="add-host" class="btn primary btn-icon">${icon('add')}<span>Add host</span></button></div>`;
  $('#add-host').onclick = () => openHost();
  $('#host-search').oninput=(e)=>{state.hostSearch=e.target.value;renderHostsContent();};
  $('#host-view').onchange=(e)=>persistHostView(e.target.value);
  renderHostsContent();
}

function certificateName(id) { return state.certificates.find((c) => c.id === id)?.name || `Certificate ${id}`; }
function providerName(id) { return state.providers.find((p) => p.id === id)?.name || 'Direct'; }
function accessListName(id) { return state.accessLists.find((a) => a.id === id)?.name || 'Public'; }
function fillAccessListSelect(selected) { $('#host-access-list').innerHTML = '<option value="">Public</option>' + state.accessLists.map((a) => `<option value="${a.id}" ${a.id === selected ? 'selected' : ''}>${esc(a.name)}</option>`).join(''); }
function fillCertificateSelect(selected) { $('#host-certificate').innerHTML = '<option value="">None</option><option value="__letsencrypt__">Create with Let\'s Encrypt</option>' + state.certificates.map((c) => `<option value="${c.id}" ${c.id === selected ? 'selected' : ''}>${esc(c.name)} · ${esc(c.provider)}</option>`).join(''); if(selected) $('#host-certificate').value=String(selected); }

function renderDomainChips() {
  $('#host-domain-chips').innerHTML = state.hostDomains.map((d,i)=>`<span class="domain-chip"><span>${esc(d)}</span><button type="button" data-domain-remove="${i}" aria-label="Remove ${esc(d)}">×</button></span>`).join('');
  $$('[data-domain-remove]').forEach((b)=>b.onclick=()=>{state.hostDomains.splice(+b.dataset.domainRemove,1);renderDomainChips();});
}
function addHostDomains(raw) {
  String(raw||'').split(/[\s,;]+/).map(x=>x.trim()).filter(Boolean).forEach((d)=>{ if(!state.hostDomains.some(x=>x.toLowerCase()===d.toLowerCase())) state.hostDomains.push(d); });
  renderDomainChips();
}
function setupDomainInput() {
  const input=$('#host-domain-input');
  input.onkeydown=(e)=>{ if((e.key==='Enter'||e.key==='Tab'||e.key===',')&&input.value.trim()){e.preventDefault();addHostDomains(input.value);input.value='';} else if(e.key==='Backspace'&&!input.value&&state.hostDomains.length){state.hostDomains.pop();renderDomainChips();} };
  input.onpaste=(e)=>{const v=e.clipboardData?.getData('text')||'';if(/[\n,;\t ]/.test(v.trim())){e.preventDefault();addHostDomains(v);input.value='';}};
  $('#host-domains').onclick=()=>input.focus();
}
function updateHostTLSChoice(){ const create=$('#host-certificate').value==='__letsencrypt__'; $('#host-acme-email-wrap').classList.toggle('hidden',!create); if(create&&!$('#host-acme-email').value) $('#host-acme-email').value=state.me?.default_acme_email||state.me?.name||''; }

function fillProviderSelect(selected) {
  $('#host-provider').innerHTML = '<option value="">Direct / None</option>' + state.providers.map((p) => `<option value="${p.id}" ${p.id === selected ? 'selected' : ''}>${esc(p.name)}</option>`).join('');
}

function setHostTab(name='general') {
  $$('.dialog-tab').forEach((b)=>b.classList.toggle('active',b.dataset.hostTab===name));
  $$('.host-tab-panel').forEach((panel)=>panel.classList.toggle('active',panel.dataset.hostPanel===name));
}
$$('.dialog-tab').forEach((b)=>b.onclick=()=>setHostTab(b.dataset.hostTab));

function openHost(h = null) {
  $('#host-form').reset();
  $('#host-error').textContent = '';
  $('#host-id').value = h?.id || '';
  $('#host-dialog-title').textContent = h ? 'Edit proxy host' : 'Add proxy host';
  setHostTab('general');
  $('#host-name').value = h?.name || '';
  state.hostDomains = arr(h?.domains).slice(); renderDomainChips(); $('#host-domain-input').value='';
  $('#host-scheme').value = h?.scheme || 'http';
  $('#host-forward').value = h?.forward_host || '';
  $('#host-port').value = h?.forward_port || 80;
  $('#host-enabled').checked = h?.enabled ?? true;
  $('#host-websockets').checked = h?.websockets ?? true;
  $('#host-preserve').checked = h?.preserve_host ?? true;
  $('#host-stats').checked = h?.statistics_enabled ?? true;
  $('#host-query').checked = h?.store_query_string ?? false;
  $('#host-exploits').checked = h?.block_common_exploits ?? false;
  fillProviderSelect(h?.trusted_proxy_provider_id || null);
  fillCertificateSelect(h?.certificate_id || null); $('#host-acme-email').value=state.me?.default_acme_email||state.me?.name||''; updateHostTLSChoice();
  fillAccessListSelect(h?.access_list_id || null);
  $('#host-ssl-forced').checked = h?.ssl_forced ?? false;
  $('#host-http2').checked = h?.http2_support ?? true;
  $('#host-hsts').checked = h?.hsts_enabled ?? false;
  $('#host-hsts-subdomains').checked = h?.hsts_subdomains ?? false;
  $('#host-cache').checked = h?.caching_enabled ?? false;
  $('#host-trust-proto').checked = h?.trust_forwarded_proto ?? false;
  $('#host-advanced').value = h?.advanced_config || '';
  $('#host-delete').classList.toggle('hidden', !h);
  $('#host-dialog').showModal();
}

$$('[data-close-dialog]').forEach((b) => { b.onclick = () => $('#host-dialog').close(); });
setupDomainInput();
$('#host-certificate').addEventListener('change', updateHostTLSChoice);
$('#host-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const id = $('#host-id').value, pid = $('#host-provider').value, certChoice = $('#host-certificate').value, aid = $('#host-access-list').value; let cid = certChoice;
  const existing = id ? state.hosts.find((h) => h.id === +id) : null;
  const body = {
    name: $('#host-name').value,
    domains: state.hostDomains.slice(),
    scheme: $('#host-scheme').value, forward_host: $('#host-forward').value, forward_port: +$('#host-port').value,
    enabled: $('#host-enabled').checked, websockets: $('#host-websockets').checked,
    preserve_host: $('#host-preserve').checked, statistics_enabled: $('#host-stats').checked,
    store_query_string: $('#host-query').checked, trusted_proxy_provider_id: pid ? +pid : null,
    block_common_exploits: $('#host-exploits').checked, certificate_id: null, access_list_id: aid ? +aid : null,
    ssl_forced: $('#host-ssl-forced').checked, http2_support: $('#host-http2').checked,
    hsts_enabled: $('#host-hsts').checked, hsts_subdomains: $('#host-hsts-subdomains').checked,
    caching_enabled: $('#host-cache').checked, trust_forwarded_proto: $('#host-trust-proto').checked,
    advanced_config: $('#host-advanced').value, custom_locations: arr(existing?.custom_locations),
  };
  try {
    if(!body.domains.length) throw new Error('At least one domain or IP is required');
    if(certChoice==='__letsencrypt__'){
      const c=await api('/api/v1/certificates/letsencrypt',{method:'POST',body:JSON.stringify({name:body.name||body.domains[0],domains:body.domains,email:$('#host-acme-email').value,challenge:'http-01',auto_renew:true})});
      body.certificate_id=c.id; body.ssl_forced=true; body.http2_support=true;
    } else body.certificate_id = cid ? +cid : null;
    await api(id ? `/api/v1/hosts/${id}` : '/api/v1/hosts', { method: id ? 'PUT' : 'POST', body: JSON.stringify(body) });
    $('#host-dialog').close();
    toast(id ? 'Host updated' : 'Host created');
    await hosts();
  } catch (err) { $('#host-error').textContent = err.message; }
});
$('#host-delete').onclick = async () => {
  const id = $('#host-id').value;
  if (!id || !confirm('Delete this proxy host?')) return;
  try {
    await api(`/api/v1/hosts/${id}`, { method: 'DELETE' });
    $('#host-dialog').close(); toast('Host deleted'); await hosts();
  } catch (e) { $('#host-error').textContent = e.message; }
};

function openEditorDialog(title, bodyHTML, {saveLabel='Save', dangerLabel='', onSave, onDanger}={}) {
  let d=$('#resource-dialog');
  if(!d){ d=document.createElement('dialog'); d.id='resource-dialog'; document.body.appendChild(d); }
  d.innerHTML=`<form id="resource-form" class="dialog-body" autocomplete="off"><div class="dialog-head"><div><h2>${esc(title)}</h2></div><button type="button" class="icon-btn" data-resource-close>×</button></div><div class="resource-form-body">${bodyHTML}</div><div id="resource-error" class="error-text"></div><div class="dialog-actions"><button type="button" class="btn" data-resource-close>Cancel</button>${dangerLabel?`<button type="button" id="resource-danger" class="btn danger">${esc(dangerLabel)}</button>`:''}<button type="submit" class="btn primary">${esc(saveLabel)}</button></div></form>`;
  d.querySelectorAll('[data-resource-close]').forEach(b=>b.onclick=()=>d.close());
  if(dangerLabel&&onDanger) $('#resource-danger').onclick=async()=>{try{await onDanger();d.close();}catch(e){$('#resource-error').textContent=e.message}};
  $('#resource-form').onsubmit=async(e)=>{e.preventDefault();$('#resource-error').textContent='';try{await onSave();d.close();}catch(err){$('#resource-error').textContent=err.message}};
  applyAutocompletePolicy(d); localize(d); d.showModal(); return d;
}

async function certificatesPage() {
  const certs = arr(await loadCertificates());
  $('#content').innerHTML = `
    <div class="grid-2">
      <form id="le-form" class="card">
        <div class="section-head"><div><h2>Let's Encrypt</h2><p class="muted">HTTP-01 by default, DNS-01 for wildcards and DNS automation.</p></div><span class="pill good">Auto renew</span></div>
        <label>Name<input id="le-name" placeholder="example.com"></label>
        <label>Domains<textarea id="le-domains" rows="3" placeholder="example.com&#10;www.example.com" required></textarea></label>
        <label>Account e-mail<input id="le-email" type="email" required value="${esc(state.me?.default_acme_email||state.me?.name||'')}" placeholder="admin@example.com"></label>
        <label>Challenge<select id="le-challenge"><option value="http-01">HTTP-01</option><option value="dns-01">DNS-01</option></select></label>
        <div id="dns-fields" class="hidden"><label>lego DNS provider<input id="le-dns-provider" placeholder="cloudflare"></label><label>DNS credential variables<textarea id="le-dns-env" rows="4" placeholder="CF_DNS_API_TOKEN=..."></textarea><small>One KEY=value per line. Stored in a 0600 file under /data, never returned by the API.</small></label></div>
        <label class="switch-row"><input id="le-auto" type="checkbox" checked><span>Automatic renewal</span><small>ZentProxy checks certificate lifetime automatically.</small></label>
        <div id="le-error" class="error-text"></div><div class="dialog-actions"><button class="btn primary">Request certificate</button></div>
      </form>
      <form id="custom-cert-form" class="card">
        <div class="section-head"><h2>Import certificate</h2><span class="pill">PEM</span></div>
        <label>Name<input id="custom-name" required></label><label>Domains<textarea id="custom-domains" rows="2" required></textarea></label>
        <label>Certificate / full chain<textarea id="custom-cert" rows="6" required></textarea></label><label>Private key<textarea id="custom-key" rows="6" required></textarea></label>
        <div id="custom-error" class="error-text"></div><div class="dialog-actions"><button class="btn primary">Import certificate</button></div>
      </form>
    </div>
    <div class="card mt16"><div class="section-head"><h2>Certificates</h2><span class="muted">${fmtNum(certs.length)} total</span></div>${certificateTable(certs)}</div>`;
  $('#le-challenge').onchange = () => $('#dns-fields').classList.toggle('hidden', $('#le-challenge').value !== 'dns-01');
  $('#le-form').onsubmit = async (e) => { e.preventDefault(); $('#le-error').textContent=''; const creds={}; $('#le-dns-env').value.split(/\n/).forEach((line)=>{const i=line.indexOf('=');if(i>0)creds[line.slice(0,i).trim()]=line.slice(i+1).trim();}); try { await api('/api/v1/certificates/letsencrypt',{method:'POST',body:JSON.stringify({name:$('#le-name').value,domains:$('#le-domains').value.split(/\n|,/).map(x=>x.trim()).filter(Boolean),email:$('#le-email').value,challenge:$('#le-challenge').value,dns_provider:$('#le-dns-provider').value,dns_credentials:creds,auto_renew:$('#le-auto').checked})}); toast('Certificate issued'); await certificatesPage(); } catch(err){$('#le-error').textContent=err.message;} };
  $('#custom-cert-form').onsubmit = async (e) => { e.preventDefault(); $('#custom-error').textContent=''; try { await api('/api/v1/certificates/import',{method:'POST',body:JSON.stringify({name:$('#custom-name').value,provider:'custom',domains:$('#custom-domains').value.split(/\n|,/).map(x=>x.trim()).filter(Boolean),certificate_pem:$('#custom-cert').value,private_key_pem:$('#custom-key').value,auto_renew:false})}); toast('Certificate imported'); await certificatesPage(); } catch(err){$('#custom-error').textContent=err.message;} };
  $$('[data-renew-cert]').forEach((b)=>{b.onclick=async()=>{b.disabled=true;try{await api(`/api/v1/certificates/${b.dataset.renewCert}/renew`,{method:'POST'});toast('Certificate renewed');await certificatesPage();}catch(e){toast(e.message)}finally{b.disabled=false}}});
  $$('[data-delete-cert]').forEach((b)=>{b.onclick=async()=>{if(!confirm('Delete this certificate?'))return;try{await api(`/api/v1/certificates/${b.dataset.deleteCert}`,{method:'DELETE'});toast('Certificate deleted');await certificatesPage();}catch(e){toast(e.message)}}});
  $$('[data-edit-cert]').forEach((b)=>{b.onclick=()=>openCertificateEditor(state.certificates.find(c=>c.id===+b.dataset.editCert));});
}
function certificateTable(certs) { certs=arr(certs); if(!certs.length)return '<div class="empty">No certificates yet.</div>'; return `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Description</th><th>Domains</th><th>Provider</th><th>Expires</th><th>Renewal</th><th></th></tr></thead><tbody>${certs.map((c)=>{const dc=arr(c.domains).length;return `<tr><td><strong>${esc(c.name)}</strong></td><td class="muted">${esc(c.description||'—')}</td><td class="certificate-domain-count">${fmtNum(dc)}</td><td>${esc(c.provider)}</td><td>${c.expires_at?new Date(c.expires_at).toLocaleString():'Unknown'}</td><td>${c.last_error?`<span class="danger-text">${esc(c.last_error)}</span>`:(c.auto_renew?'<span class="good-text">Automatic</span>':'Manual')}</td><td><div class="inline-actions"><button class="btn small" data-edit-cert="${c.id}">Edit</button>${c.provider.includes('letsencrypt')?`<button class="btn small" data-renew-cert="${c.id}">Renew</button>`:''}<button class="btn small danger" data-delete-cert="${c.id}">Delete</button></div></td></tr>`}).join('')}</tbody></table></div>`; }

async function analytics() {
  const hostsRaw = await api('/api/v1/hosts');
  const configuredHosts = arr(hostsRaw);
  const configuredDomains = [...new Set(configuredHosts.flatMap((h) => arr(h.domains)).filter((d) => d && !d.startsWith('*.')))].sort((a,b)=>a.localeCompare(b));
  let ticking = null;

  const query = () => {
    const q = new URLSearchParams({ range: state.analyticsRange });
    if (state.analyticsHost) q.set('host', state.analyticsHost);
    return q.toString();
  };

  const draw = async (preserveControls = false) => {
    const [statsRaw, reqsRaw] = await Promise.all([
      api(`/api/v1/stats/summary?${query()}`), api(`/api/v1/stats/requests?${query()}&limit=100`),
    ]);
    const stats = obj(statsRaw), reqs = arr(reqsRaw);
    const hostOptions = [...new Set([...configuredDomains, ...arr(stats.top_hosts).map((x)=>x.key).filter(Boolean)])].sort((a,b)=>a.localeCompare(b));
    const updated = new Date();
    $('#content').innerHTML = `
      <div class="analytics-toolbar card">
        <div class="analytics-controls">
          <label>Period<select id="analytics-range"><option value="1h" ${state.analyticsRange==='1h'?'selected':''}>1h</option><option value="24h" ${state.analyticsRange==='24h'?'selected':''}>24h</option><option value="7d" ${state.analyticsRange==='7d'?'selected':''}>7d</option><option value="30d" ${state.analyticsRange==='30d'?'selected':''}>30d</option></select></label>
          <label>Domain<input id="analytics-host" list="analytics-hosts" value="${esc(state.analyticsHost)}" placeholder="All domains"><datalist id="analytics-hosts">${hostOptions.map((h)=>`<option value="${esc(h)}"></option>`).join('')}</datalist></label>
          <button id="analytics-apply" class="btn" type="button">Apply</button>
        </div>
        <div class="analytics-refresh-state">
          <button id="analytics-auto" class="btn small ${state.analyticsAuto?'active':''}" type="button"><span class="status-dot ${state.analyticsAuto?'ok':'off'}"></span> Auto refresh: <strong>${state.analyticsAuto?'ON':'OFF'}</strong></button>
          <span id="analytics-refresh-meta" class="muted">Updated ${updated.toLocaleTimeString()}${state.analyticsAuto ? ` · next in ${state.analyticsCountdown}s` : ''}</span>
        </div>
      </div>
      <div class="cards">${metric('requests', 'Requests', fmtNum(stats.requests))}${metric('clients', 'Clients', fmtNum(stats.unique_ips))}${metric('traffic', 'Traffic', fmtBytes(stats.bytes))}${metric('status', 'Avg response', `${num(stats.average_time_ms).toFixed(1)} ms`)}</div>
      <div class="grid-2 analytics-grid">
        <div class="card">${sectionHeading('proxy-hosts', 'Top domains')}${domainCountList(arr(stats.top_hosts))}</div>
        <div class="card">${sectionHeading('ip', 'Top client IPs')}${countList(arr(stats.top_ips))}</div>
      </div>
      <div class="grid-2 analytics-grid">
        <div class="card">${sectionHeading('paths', 'Top paths')}${countList(arr(stats.top_paths))}</div>
        <div class="card">${sectionHeading('status', 'Status codes')}${statusBars(obj(stats.status_classes), num(stats.requests))}</div>
      </div>
      <div class="card">${sectionHeading('requests', 'Recent requests')}${requestTable(reqs)}</div>`;

    $('#analytics-range').onchange = (e) => { state.analyticsRange = e.target.value; };
    $('#analytics-host').oninput = (e) => { state.analyticsHost = e.target.value.trim(); };
    $('#analytics-apply').onclick = async () => { state.analyticsCountdown = 5; await draw(); };
    $$('[data-analytics-domain]').forEach((b) => { b.onclick = async () => { state.analyticsHost = b.dataset.analyticsDomain || ''; state.analyticsCountdown = 5; await draw(); }; });
    $('#analytics-auto').onclick = () => {
      state.analyticsAuto = !state.analyticsAuto;
      state.analyticsCountdown = 5;
      const b = $('#analytics-auto');
      b.classList.toggle('active', state.analyticsAuto);
      b.innerHTML = `<span class="status-dot ${state.analyticsAuto?'ok':'off'}"></span> Auto refresh: <strong>${state.analyticsAuto?'ON':'OFF'}</strong>`;
      const m = $('#analytics-refresh-meta');
      if (m) m.textContent = `Updated ${updated.toLocaleTimeString()}${state.analyticsAuto ? ` · next in ${state.analyticsCountdown}s` : ''}`;
    };
    localize($('#content'));
  };

  await draw();
  state.poll = setInterval(async () => {
    if (state.page !== 'analytics') return;
    if (!state.analyticsAuto) return;
    state.analyticsCountdown -= 1;
    const meta = $('#analytics-refresh-meta');
    if (state.analyticsCountdown > 0) {
      if (meta) meta.textContent = `${tr('Auto refresh active')} · ${tr('next in')} ${state.analyticsCountdown}s`;
      return;
    }
    state.analyticsCountdown = 5;
    try { await draw(true); } catch {}
  }, 1000);
}

function requestTable(rs) {
  rs = arr(rs);
  if (!rs.length) return '<div class="empty">No requests recorded yet.</div>';
  return `<div class="table-wrap"><table><thead><tr><th>Time</th><th>Host</th><th>Client IP</th><th>Method</th><th>Path</th><th>Status</th><th>Time</th></tr></thead><tbody>${rs.map((r) => `<tr><td>${new Date(r.at).toLocaleTimeString()}</td><td>${esc(r.host)}</td><td class="code">${esc(r.ip)}</td><td>${esc(r.method)}</td><td class="code">${esc(r.path)}${r.query ? '?' + esc(r.query) : ''}</td><td><span class="pill ${r.status < 400 ? 'good' : r.status >= 500 ? 'warn' : ''}">${num(r.status)}</span></td><td>${num(r.request_time_ms).toFixed(1)} ms</td></tr>`).join('')}</tbody></table></div>`;
}

async function providers() {
  const [psRaw, hsRaw] = await Promise.all([loadProviders(), api('/api/v1/hosts')]);
  const ps = arr(psRaw), hs = arr(hsRaw); state.hosts = hs;
  $('#top-actions').innerHTML = `<button id="add-provider" class="btn primary btn-icon">${icon('plus')}<span>Add provider</span></button>`;
  const usageCount = (id) => hs.filter(h => h.trusted_proxy_provider_id === id).length;
  $('#content').innerHTML = `<div class="card">${sectionHeading('trusted-proxies', 'Trusted proxy providers', '<span class="muted">Define trusted proxy or CDN networks for real client IP detection. A provider only takes effect when selected on a Proxy Host.</span>')}<div class="table-wrap"><table><thead><tr><th>Provider</th><th>Client IP header</th><th>Ranges</th><th>Used by hosts</th><th>Status</th><th></th></tr></thead><tbody>${ps.map((p) => {
    const builtin = p.slug === 'cloudflare' || p.kind !== 'manual';
    const status = p.last_error ? `<span class="danger-text">${esc(p.last_error)}</span>` : (builtin ? '<span class="good-text">Automatically maintained</span>' : '<span class="good-text">Manual</span>');
    const actions = builtin
      ? `<button class="btn small btn-icon" data-refresh-provider="${p.id}">${icon('refresh')}<span>Refresh</span></button>`
      : `<button class="btn small" data-edit-provider="${p.id}">Edit</button><button class="btn small danger" data-delete-provider="${p.id}">Delete</button>`;
    return `<tr><td><strong>${esc(p.name)}</strong><div class="tiny muted">${builtin ? 'Built-in provider' : 'Custom provider'}</div></td><td class="code">${esc(p.header)}</td><td>${fmtNum(arr(p.cidrs).length)}</td><td>${fmtNum(usageCount(p.id))}</td><td>${status}</td><td><div class="inline-actions">${actions}</div></td></tr>`;
  }).join('')}</tbody></table></div></div>`;
  $('#add-provider').onclick = () => openProviderEditor();
  $$('[data-refresh-provider]').forEach((b) => {
    b.onclick = async () => {
      b.disabled = true;
      try { await api(`/api/v1/trusted-proxy-providers/${b.dataset.refreshProvider}/refresh`, { method: 'POST' }); toast('Provider ranges refreshed'); await providers(); }
      catch (e) { toast(e.message); }
      finally { b.disabled = false; }
    };
  });
  $$('[data-edit-provider]').forEach((b) => b.onclick = () => openProviderEditor(ps.find(p => p.id === +b.dataset.editProvider)));
  $$('[data-delete-provider]').forEach((b) => b.onclick = async () => {
    const p = ps.find(x => x.id === +b.dataset.deleteProvider); if (!p) return;
    const used = usageCount(p.id);
    const message = used ? `${tr('Delete')} ${p.name}? ${used} ${tr('Proxy Host(s) will automatically switch to Direct / None.')}` : `${tr('Delete')} ${p.name}?`;
    if (!confirm(message)) return;
    try { const result = await api(`/api/v1/trusted-proxy-providers/${p.id}`, {method:'DELETE'}); toast(result.hosts_reset ? `${tr('Provider deleted')} · ${result.hosts_reset} ${tr('host(s) reset to Direct / None')}` : tr('Provider deleted')); await providers(); }
    catch(e){ toast(e.message); }
  });
}

function openProviderEditor(p=null) {
  if (p && (p.slug === 'cloudflare' || p.kind !== 'manual')) return;
  openEditorDialog(p ? 'Edit trusted proxy provider' : 'Add trusted proxy provider', `
    <label>Name<input id="provider-name" value="${esc(p?.name||'')}" placeholder="Office reverse proxy" required></label>
    <label>Client IP header<input id="provider-header" value="${esc(p?.header||'X-Forwarded-For')}" placeholder="X-Forwarded-For" required><small>The header that contains the original client IP after traffic passed through this provider.</small></label>
    <label>Trusted IP addresses / CIDRs<textarea id="provider-cidrs" rows="9" placeholder="10.0.0.10&#10;192.168.1.0/24&#10;2001:db8::/32" required>${esc(arr(p?.cidrs).join('\n'))}</textarea><small>One IPv4/IPv6 address or CIDR per line. Individual addresses are normalized to /32 or /128.</small></label>
    <div class="info-banner">Providers are inactive by default. Select this provider explicitly on the Proxy Hosts that should trust it.</div>`, {
      saveLabel: p ? 'Save changes' : 'Add provider',
      onSave: async () => {
        const body = {name: $('#provider-name').value.trim(), header: $('#provider-header').value.trim(), cidrs: $('#provider-cidrs').value.split(/\n|,/).map(x=>x.trim()).filter(Boolean)};
        await api(p ? `/api/v1/trusted-proxy-providers/${p.id}` : '/api/v1/trusted-proxy-providers', {method:p?'PUT':'POST', body:JSON.stringify(body)});
        toast(p ? 'Provider updated' : 'Provider created'); await providers();
      }
    });
}

function openCertificateEditor(c){
  if(!c)return;
  openEditorDialog('Edit certificate',`<label>Name<input id="cert-edit-name" value="${esc(c.name)}" required></label><label>Description<textarea id="cert-edit-description" rows="4" placeholder="What is this certificate used for?">${esc(c.description||'')}</textarea></label><div class="readonly-box"><div><span class="muted">Provider</span><strong>${esc(c.provider)}</strong></div><div class="readonly-domains"><span class="muted">Domains / SANs · ${fmtNum(arr(c.domains).length)}</span><div class="domain-chip-list">${arr(c.domains).map(d=>`<span class="domain-chip static">${esc(d)}</span>`).join('')||'<span class="muted">No names available</span>'}</div></div></div>`,{onSave:async()=>{await api(`/api/v1/certificates/${c.id}`,{method:'PUT',body:JSON.stringify({name:$('#cert-edit-name').value,description:$('#cert-edit-description').value})});toast('Certificate updated');await certificatesPage();}});
}

async function zentloop() {
  const [hRaw, hostsRaw] = await Promise.all([api('/api/v1/integrations/zentloop'), api('/api/v1/hosts')]);
  const h=obj(hRaw), hs=arr(hostsRaw); state.hosts=hs;
  const listRow=(l={name:'',entries:[]})=>`<div class="zentloop-list-row card-sub"><div class="form-grid"><label>List name<input data-zentloop-list-name value="${esc(l.name||'')}" placeholder="Known scanners"></label><label class="span-2">IP addresses / CIDRs<textarea data-zentloop-list-entries rows="2" placeholder="185.1.2.3&#10;91.0.0.0/8">${esc(arr(l.entries).join('\n'))}</textarea></label></div><button type="button" class="btn small danger" data-remove-zentloop-list>Remove list</button></div>`;
  const ruleRow=(r={name:'',enabled:true,match:'path_exact',value:'',action:'zentloop',host_ids:[]})=>`<div class="zentloop-rule-row card-sub zentloop-rule-grid"><label>Name<input data-zentloop-rule-name value="${esc(r.name||'')}" placeholder="Environment probes"></label><label>Match<select data-zentloop-rule-match><option value="source_ip_list" ${r.match==='source_ip_list'?'selected':''}>Source IP in list</option><option value="path_exact" ${r.match==='path_exact'?'selected':''}>Path equals</option><option value="path_prefix" ${r.match==='path_prefix'?'selected':''}>Path starts with</option></select></label><label class="rule-wide">Value<input data-zentloop-rule-value value="${esc(r.value||'')}" placeholder="/.env or list name"></label><label>Action<select data-zentloop-rule-action><option value="zentloop" ${r.action!=='block'?'selected':''}>ZentLoop</option><option value="block" ${r.action==='block'?'selected':''}>Block 403</option></select></label><label>Proxy host<select data-zentloop-rule-host><option value="">All hosts</option>${hs.map(x=>`<option value="${x.id}" ${arr(r.host_ids).includes(x.id)?'selected':''}>${esc(x.name)}</option>`).join('')}</select></label><label class="switch-row compact"><input data-zentloop-rule-enabled type="checkbox" ${r.enabled!==false?'checked':''}><span>Enabled</span></label><button type="button" class="btn small danger" data-remove-zentloop-rule>×</button></div>`;
  const zh=obj(h.health), zStatus=zh.status||'unknown';
  const statusClass=zStatus==='online'?'good':(zStatus==='degraded'?'warn':'');
  const verification=zh.verification==='verified'?'Secret verified':zh.verification==='secret_mismatch'?'Secret mismatch':zh.verification==='unverified'?'Signature not confirmed':zh.verification==='not_configured'?'No signing secret':zh.verification==='disabled'?'Disabled':zh.verification==='unreachable'?'Unreachable':'Not checked';
  const healthCard=`<div class="zentloop-health-card"><div class="section-head"><div><h3>Connection status</h3><p class="muted">ZentProxy checks reachability and signed integration verification every 15 seconds.</p></div><div class="section-actions"><span class="pill ${statusClass}">${esc(zStatus)}</span><button id="zentloop-check-now" class="btn small" type="button">Check now</button></div></div><div class="health-grid"><div><span class="muted">Reachability</span><strong>${zh.reachable?'Reachable':'Unavailable'}</strong></div><div><span class="muted">Signature</span><strong>${esc(verification)}</strong></div><div><span class="muted">Latency</span><strong>${zh.latency_ms!=null?esc(String(zh.latency_ms))+' ms':'—'}</strong></div><div><span class="muted">Last check</span><strong>${zh.last_checked?new Date(zh.last_checked).toLocaleString():'—'}</strong></div></div>${zh.error?`<div class="info-banner warn-banner">${esc(zh.error)}</div>`:''}</div>`;
  const tabs=h.enabled?`<div class="dialog-tabs zentloop-tabs" role="tablist"><button type="button" class="dialog-tab active" data-zentloop-tab="integration">ZentLoop integration</button><button type="button" class="dialog-tab" data-zentloop-tab="lists">IP / CIDR lists</button><button type="button" class="dialog-tab" data-zentloop-tab="rules">Routing rules</button></div>`:'';
  $('#content').innerHTML=`<form id="zentloop-form" class="zentloop-page-stack">
    ${tabs}
    <section class="zentloop-tab-panel active" data-zentloop-panel="integration"><div class="card max980"><div class="section-head"><div><h2 class="section-title"><span class="section-icon">${icon('zentloop')}</span>ZentLoop integration</h2><p class="muted">Configure routing, authentication and failure behavior. ZentProxy never waits indefinitely for an unavailable ZentLoop upstream.</p></div><span class="pill ${h.enabled?'good':''}">${h.enabled?'Enabled':'Disabled'}</span></div><label class="switch-row"><input id="zentloop-enabled" type="checkbox" ${h.enabled?'checked':''}><span>Enable ZentLoop routing</span><small>Enables catch-all routing and explicit rule actions that target ZentLoop.</small></label><label>Upstream URL<input id="zentloop-upstream" value="${esc(h.upstream||'http://zentloop:8080')}" placeholder="http://zentloop:8080"></label><label>Shared signing secret<input id="zentloop-secret" type="password" value="${esc(h.secret||'')}" placeholder="Optional on private Docker networks"><small>When set, ZentProxy signs integration metadata with HMAC-SHA256. The health check verifies that ZentLoop accepts the same secret.</small></label><label>When ZentLoop is unavailable<select id="zentloop-fallback"><option value="block" ${h.fallback!=='503'?'selected':''}>Block request (403)</option><option value="503" ${h.fallback==='503'?'selected':''}>Return 503 Service Unavailable</option></select><small>Explicit ZentLoop routes fail closed; no request is sent to an unavailable integration.</small></label>${h.enabled?healthCard:''}</div></section>
    <section class="zentloop-tab-panel" data-zentloop-panel="lists"><div class="card max980"><div class="section-head"><div><h2>IP / CIDR lists</h2><p class="muted">Reusable source-IP lists. Trusted Proxy resolution happens first, so Cloudflare visitors are matched by their real client IP.</p></div><button id="add-zentloop-list" class="btn small" type="button">Add list</button></div><div id="zentloop-lists" class="zentloop-editor-stack">${arr(h.ip_lists).map(listRow).join('')||listRow()}</div></div></section>
    <section class="zentloop-tab-panel" data-zentloop-panel="rules"><div class="card max980"><div class="section-head"><div><h2>Routing rules</h2><p class="muted">Match an IP list or suspicious path and route it directly to ZentLoop, or block it. Empty host means all proxy hosts.</p></div><button id="add-zentloop-rule" class="btn small" type="button">Add rule</button></div><div id="zentloop-rules" class="zentloop-editor-stack">${arr(h.rules).map(ruleRow).join('')||ruleRow()}</div></div></section>
    <div id="zentloop-error" class="error-text"></div><div class="dialog-actions max980"><button class="btn primary btn-icon" type="submit">${icon('zentloop')}<span>Save integration</span></button></div></form>`;
  const showTab=(name)=>{$$('[data-zentloop-tab]').forEach(b=>b.classList.toggle('active',b.dataset.zentloopTab===name));$$('[data-zentloop-panel]').forEach(p=>p.classList.toggle('active',p.dataset.zentloopPanel===name));};
  $$('[data-zentloop-tab]').forEach(b=>b.onclick=()=>showTab(b.dataset.zentloopTab));
  const wire=()=>{$$('[data-remove-zentloop-list]').forEach(b=>b.onclick=()=>b.closest('.zentloop-list-row').remove());$$('[data-remove-zentloop-rule]').forEach(b=>b.onclick=()=>b.closest('.zentloop-rule-row').remove());};
  wire();
  const addListButton=$('#add-zentloop-list'), addRuleButton=$('#add-zentloop-rule');
  if(addListButton)addListButton.onclick=()=>{$('#zentloop-lists').insertAdjacentHTML('beforeend',listRow());wire();};
  if(addRuleButton)addRuleButton.onclick=()=>{$('#zentloop-rules').insertAdjacentHTML('beforeend',ruleRow());wire();};
  const checkButton=$('#zentloop-check-now');
  if(checkButton)checkButton.onclick=async()=>{checkButton.disabled=true;checkButton.textContent='Checking…';try{await api('/api/v1/integrations/zentloop/check',{method:'POST'});await zentloop();}catch(err){toast(err.message);}finally{checkButton.disabled=false;}};
  $('#zentloop-form').onsubmit=async(e)=>{
    e.preventDefault();$('#zentloop-error').textContent='';
    const ip_lists=$$('.zentloop-list-row').map(row=>({name:row.querySelector('[data-zentloop-list-name]').value.trim(),entries:row.querySelector('[data-zentloop-list-entries]').value.split(/[\n,]+/).map(x=>x.trim()).filter(Boolean)})).filter(x=>x.name||x.entries.length);
    const rules=$$('.zentloop-rule-row').map(row=>{const hv=row.querySelector('[data-zentloop-rule-host]').value;return{name:row.querySelector('[data-zentloop-rule-name]').value.trim(),enabled:row.querySelector('[data-zentloop-rule-enabled]').checked,match:row.querySelector('[data-zentloop-rule-match]').value,value:row.querySelector('[data-zentloop-rule-value]').value.trim(),action:row.querySelector('[data-zentloop-rule-action]').value,host_ids:hv?[+hv]:[]};}).filter(x=>x.name||x.value);
    try{await api('/api/v1/integrations/zentloop',{method:'PUT',body:JSON.stringify({enabled:$('#zentloop-enabled').checked,upstream:$('#zentloop-upstream').value,secret:$('#zentloop-secret').value,fallback:$('#zentloop-fallback').value,ip_lists,rules})});toast('ZentLoop integration saved');await zentloop();}
    catch(err){$('#zentloop-error').textContent=err.message;}
  };
}

function domainsText(v){return arr(v).join('\n')}
function parseDomains(v){return String(v||'').split(/[\n,;\s]+/).map(x=>x.trim()).filter(Boolean)}
function checkbox(id,v){return `<label class="switch-row"><input id="${id}" type="checkbox" ${v?'checked':''}><span>Enabled</span></label>`}

async function routingPage() {
  const [redirectsRaw, deadRaw, streamsRaw] = await Promise.all([api('/api/v1/redirect-hosts'),api('/api/v1/dead-hosts'),api('/api/v1/streams')]);
  const rs=arr(redirectsRaw), ds=arr(deadRaw), ss=arr(streamsRaw);
  $('#content').innerHTML=`<div class="cards routing-metrics">${metric('redirect','Redirect hosts',fmtNum(rs.length))}${metric('dead-host','404 hosts',fmtNum(ds.length))}${metric('stream','Streams',fmtNum(ss.length))}</div>
    <div class="management-stack">
      <div class="card"><div class="section-head"><div><h2>Redirect hosts</h2><p class="muted">HTTP redirects with optional TLS settings.</p></div><button id="add-redirect" class="btn small btn-icon">${icon('add')}<span>Add redirect</span></button></div>${rs.length?`<div class="table-wrap"><table><thead><tr><th>Domains</th><th>Target</th><th>Code</th><th>Status</th><th></th></tr></thead><tbody>${rs.map(x=>`<tr class="clickable-row" data-edit-redirect="${x.id}"><td>${arr(x.domains).map(d=>`<span class="pill">${esc(d)}</span>`).join(' ')}</td><td class="code">${esc(x.forward_scheme)}://${esc(x.forward_domain_name)}</td><td>${x.forward_http_code}</td><td>${x.enabled?'<span class="good-text">Enabled</span>':'Disabled'}</td><td class="row-chevron">›</td></tr>`).join('')}</tbody></table></div>`:emptyState('redirect','No redirect hosts.')}</div>
      <div class="card"><div class="section-head"><div><h2>404 hosts</h2><p class="muted">Explicit hostnames that should return ZentProxy's 404 response.</p></div><button id="add-dead" class="btn small btn-icon">${icon('add')}<span>Add 404 host</span></button></div>${ds.length?`<div class="table-wrap"><table><thead><tr><th>Domains</th><th>Status</th><th></th></tr></thead><tbody>${ds.map(x=>`<tr class="clickable-row" data-edit-dead="${x.id}"><td>${arr(x.domains).map(d=>`<span class="pill">${esc(d)}</span>`).join(' ')}</td><td>${x.enabled?'<span class="good-text">Enabled</span>':'Disabled'}</td><td class="row-chevron">›</td></tr>`).join('')}</tbody></table></div>`:emptyState('dead-host','No 404 hosts.')}</div>
      <div class="card"><div class="section-head"><div><h2>Streams</h2><p class="muted">TCP/UDP forwarding. Docker or Unraid must also publish the incoming port.</p></div><button id="add-stream" class="btn small btn-icon">${icon('add')}<span>Add stream</span></button></div>${ss.length?`<div class="table-wrap"><table><thead><tr><th>Incoming</th><th>Target</th><th>Protocol</th><th>Status</th><th></th></tr></thead><tbody>${ss.map(x=>`<tr class="clickable-row" data-edit-stream="${x.id}"><td class="code">:${num(x.incoming_port)}</td><td class="code">${esc(x.forward_host)}:${num(x.forward_port)}</td><td>${x.tcp_forwarding?'TCP ':''}${x.udp_forwarding?'UDP':''}</td><td>${x.enabled?'<span class="good-text">Enabled</span>':'Disabled'}</td><td class="row-chevron">›</td></tr>`).join('')}</tbody></table></div>`:emptyState('stream','No streams.')}</div>
    </div>`;
  $('#add-redirect').onclick=()=>openRedirectEditor(); $('#add-dead').onclick=()=>openDeadEditor(); $('#add-stream').onclick=()=>openStreamEditor();
  $$('[data-edit-redirect]').forEach(r=>r.onclick=()=>openRedirectEditor(rs.find(x=>x.id===+r.dataset.editRedirect)));
  $$('[data-edit-dead]').forEach(r=>r.onclick=()=>openDeadEditor(ds.find(x=>x.id===+r.dataset.editDead)));
  $$('[data-edit-stream]').forEach(r=>r.onclick=()=>openStreamEditor(ss.find(x=>x.id===+r.dataset.editStream)));
}
function openRedirectEditor(x=null){const v=x||{domains:[],forward_http_code:301,forward_scheme:'https',forward_domain_name:'',preserve_path:true,certificate_id:null,ssl_forced:false,http2_support:false,hsts_enabled:false,hsts_subdomains:false,block_exploits:false,advanced_config:'',enabled:true};openEditorDialog(x?'Edit redirect host':'Add redirect host',`<label>Domains<textarea id="route-domains" rows="3" placeholder="old.example.com" required>${esc(domainsText(v.domains))}</textarea></label><div class="form-grid"><label>Target scheme<select id="route-scheme"><option value="auto" ${v.forward_scheme==='auto'?'selected':''}>auto</option><option value="https" ${v.forward_scheme==='https'?'selected':''}>https</option><option value="http" ${v.forward_scheme==='http'?'selected':''}>http</option></select></label><label>Target domain<input id="route-target" value="${esc(v.forward_domain_name)}" required></label><label>HTTP code<select id="route-code">${[301,302,307,308].map(n=>`<option ${v.forward_http_code===n?'selected':''}>${n}</option>`).join('')}</select></label></div><div class="switch-grid"><label class="switch-row"><input id="route-preserve" type="checkbox" ${v.preserve_path?'checked':''}><span>Preserve path</span></label>${checkbox('route-enabled',v.enabled)}</div>`,{dangerLabel:x?'Delete':'',onDanger:x?async()=>{if(!confirm('Delete this redirect host?'))throw new Error('Cancelled');await api(`/api/v1/redirect-hosts/${x.id}`,{method:'DELETE'});toast('Redirect deleted');await routingPage()}:null,onSave:async()=>{const body={domains:parseDomains($('#route-domains').value),forward_http_code:+$('#route-code').value,forward_scheme:$('#route-scheme').value,forward_domain_name:$('#route-target').value.trim(),preserve_path:$('#route-preserve').checked,certificate_id:v.certificate_id??null,ssl_forced:!!v.ssl_forced,http2_support:!!v.http2_support,hsts_enabled:!!v.hsts_enabled,hsts_subdomains:!!v.hsts_subdomains,block_exploits:!!v.block_exploits,advanced_config:v.advanced_config||'',enabled:$('#route-enabled').checked};await api(x?`/api/v1/redirect-hosts/${x.id}`:'/api/v1/redirect-hosts',{method:x?'PUT':'POST',body:JSON.stringify(body)});toast(x?'Redirect updated':'Redirect created');await routingPage();}})}
function openDeadEditor(x=null){const v=x||{domains:[],certificate_id:null,ssl_forced:false,http2_support:false,hsts_enabled:false,hsts_subdomains:false,advanced_config:'',enabled:true};openEditorDialog(x?'Edit 404 host':'Add 404 host',`<label>Domains<textarea id="dead-domains" rows="4" placeholder="unused.example.com" required>${esc(domainsText(v.domains))}</textarea></label>${checkbox('dead-enabled',v.enabled)}`,{dangerLabel:x?'Delete':'',onDanger:x?async()=>{if(!confirm('Delete this 404 host?'))throw new Error('Cancelled');await api(`/api/v1/dead-hosts/${x.id}`,{method:'DELETE'});toast('404 host deleted');await routingPage()}:null,onSave:async()=>{const body={domains:parseDomains($('#dead-domains').value),certificate_id:v.certificate_id??null,ssl_forced:!!v.ssl_forced,http2_support:!!v.http2_support,hsts_enabled:!!v.hsts_enabled,hsts_subdomains:!!v.hsts_subdomains,advanced_config:v.advanced_config||'',enabled:$('#dead-enabled').checked};await api(x?`/api/v1/dead-hosts/${x.id}`:'/api/v1/dead-hosts',{method:x?'PUT':'POST',body:JSON.stringify(body)});toast(x?'404 host updated':'404 host created');await routingPage();}})}
function openStreamEditor(x=null){const v=x||{incoming_port:0,forward_host:'',forward_port:0,tcp_forwarding:true,udp_forwarding:false,certificate_id:null,enabled:true};openEditorDialog(x?'Edit stream':'Add stream',`<div class="form-grid"><label>Incoming port<input id="stream-in" type="number" min="1" max="65535" value="${num(v.incoming_port)||''}" required></label><label>Forward host<input id="stream-host" value="${esc(v.forward_host)}" required></label><label>Forward port<input id="stream-port" type="number" min="1" max="65535" value="${num(v.forward_port)||''}" required></label></div><div class="switch-grid"><label class="switch-row"><input id="stream-tcp" type="checkbox" ${v.tcp_forwarding?'checked':''}><span>TCP</span></label><label class="switch-row"><input id="stream-udp" type="checkbox" ${v.udp_forwarding?'checked':''}><span>UDP</span></label>${checkbox('stream-enabled',v.enabled)}</div>`,{dangerLabel:x?'Delete':'',onDanger:x?async()=>{if(!confirm('Delete this stream?'))throw new Error('Cancelled');await api(`/api/v1/streams/${x.id}`,{method:'DELETE'});toast('Stream deleted');await routingPage()}:null,onSave:async()=>{const body={incoming_port:+$('#stream-in').value,forward_host:$('#stream-host').value.trim(),forward_port:+$('#stream-port').value,tcp_forwarding:$('#stream-tcp').checked,udp_forwarding:$('#stream-udp').checked,certificate_id:v.certificate_id??null,enabled:$('#stream-enabled').checked};await api(x?`/api/v1/streams/${x.id}`:'/api/v1/streams',{method:x?'PUT':'POST',body:JSON.stringify(body)});toast(x?'Stream updated':'Stream created');await routingPage();}})}

async function accessListsPage(){
  const lists=arr(await api('/api/v1/access-lists')); state.accessLists=lists;
  $('#top-actions').innerHTML=`<button id="add-access-list" class="btn primary btn-icon">${icon('add')}<span>Add access list</span></button>`;
  $('#content').innerHTML=lists.length?`<div class="management-stack">${lists.map(x=>`<div class="card clickable-card" data-access-list="${x.id}"><div class="section-head"><div><h2>${esc(x.name)}</h2><p class="muted">${arr(x.rules).filter(r=>r.directive==='allow').length} allow · ${arr(x.rules).filter(r=>r.directive==='deny').length} deny${x.auth_enabled?' · Login required':''}</p></div><span class="row-chevron">›</span></div><div class="pill-row">${arr(x.rules).slice(0,8).map(r=>`<span class="pill ${r.directive==='allow'?'good':'warn'}">${esc(r.directive)} ${esc(r.address)}</span>`).join(' ')}</div></div>`).join('')}</div>`:emptyState('access','No access lists.');
  $('#add-access-list').onclick=()=>openAccessListEditor(); $$('[data-access-list]').forEach(el=>el.onclick=()=>openAccessListEditor(lists.find(x=>x.id===+el.dataset.accessList)));
}
async function openAccessListEditor(x=null){
  const v=x||{name:'',satisfy_any:false,pass_auth:false,auth_enabled:false,rules:[],auth_file:''};
  const existingUsers=x?arr(await api(`/api/v1/access-lists/${x.id}/users`)):[];
  const allows=arr(v.rules).filter(r=>r.directive==='allow').map(r=>r.address).join('\n');
  const denies=arr(v.rules).filter(r=>r.directive==='deny').map(r=>r.address).join('\n');
  const userRows=existingUsers.map(u=>`<div class="credential-row" data-existing-user="${esc(u)}"><div class="credential-user">${esc(u)}</div><input type="password" autocomplete="new-password" placeholder="New password (leave blank to keep)"><button type="button" class="btn small danger credential-remove">Remove</button></div>`).join('');
  const d=openEditorDialog(x?'Edit access list':'Add access list',`
    <label>Name<input id="access-name" value="${esc(v.name)}" required></label>
    <section class="access-editor-section"><h3>IP access</h3><p class="muted">Maintain allow and deny networks separately. One IP or CIDR per line.</p><div class="access-rule-columns"><label>Allow list<textarea id="access-allow" rows="6" placeholder="192.168.1.0/24&#10;10.0.0.5">${esc(allows)}</textarea></label><label>Deny list<textarea id="access-deny" rows="6" placeholder="0.0.0.0/0&#10;2001:db8::/32">${esc(denies)}</textarea></label></div></section>
    <section class="access-editor-section"><h3>Login credentials</h3><p class="muted">Optionally require a username and password. Passwords are stored as bcrypt hashes in the managed access file.</p><label class="switch-row"><input id="access-auth-enabled" type="checkbox" ${v.auth_enabled?'checked':''}><span>Require username and password</span><small>Can be used alone or together with IP rules.</small></label><div id="access-credentials" class="credential-list">${userRows}</div><div class="form-grid"><label>Username<input id="access-new-user" placeholder="username"></label><label>Password<input id="access-new-pass" type="password" autocomplete="new-password" placeholder="At least 8 characters"></label></div><button type="button" id="access-add-user" class="btn small">Add credential</button></section>
    <section id="access-combination" class="access-editor-section"><h3>When IP rules and login are both used</h3><div class="access-mode-row"><label class="switch-row"><input name="access-mode" id="access-mode-all" type="radio" ${v.satisfy_any?'':'checked'}><span>Both required</span><small>The client must satisfy the IP rules and provide valid credentials.</small></label><label class="switch-row"><input name="access-mode" id="access-mode-any" type="radio" ${v.satisfy_any?'checked':''}><span>Either is enough</span><small>Allow when the IP rules or valid credentials match.</small></label></div></section>
    <label class="switch-row"><input id="access-pass-auth" type="checkbox" ${v.pass_auth?'checked':''}><span>Forward Authorization header</span><small>Pass the client's Authorization header to the upstream application.</small></label>`,{
      dangerLabel:x?'Delete':'',
      onDanger:x?async()=>{if(!confirm('Delete this access list?'))throw new Error('Cancelled');await api(`/api/v1/access-lists/${x.id}`,{method:'DELETE'});toast('Access list deleted');await accessListsPage()}:null,
      onSave:async()=>{
        const parseLines=(id,directive)=>$('#'+id).value.split(/\n|,/).map(v=>v.trim()).filter(Boolean).map(address=>({directive,address}));
        const rules=[...parseLines('access-allow','allow'),...parseLines('access-deny','deny')];
        const pendingRows=Array.from($$('#access-credentials .credential-row'));
        const activeExisting=pendingRows.filter(row=>row.dataset.existingUser&&!row.dataset.remove).map(row=>row.dataset.existingUser);
        const stagedNew=pendingRows.filter(row=>row.dataset.newUser&&!row.dataset.remove).map(row=>({username:row.dataset.newUser,password:row.dataset.password||''}));
        const authEnabled=$('#access-auth-enabled').checked;
        if(authEnabled && activeExisting.length+stagedNew.length===0) throw new Error('Add at least one username/password or disable login credentials.');
        const body={name:$('#access-name').value.trim(),satisfy_any:$('#access-mode-any').checked,pass_auth:$('#access-pass-auth').checked,auth_enabled:authEnabled,rules};
        const saved=await api(x?`/api/v1/access-lists/${x.id}`:'/api/v1/access-lists',{method:x?'PUT':'POST',body:JSON.stringify(body)});
        const id=saved.id;
        for(const row of pendingRows){
          if(row.dataset.existingUser){
            if(row.dataset.remove){await api(`/api/v1/access-lists/${id}/users/${encodeURIComponent(row.dataset.existingUser)}`,{method:'DELETE'});continue;}
            const pass=row.querySelector('input[type=password]')?.value||'';
            if(pass) await api(`/api/v1/access-lists/${id}/users/${encodeURIComponent(row.dataset.existingUser)}`,{method:'PUT',body:JSON.stringify({password:pass})});
          } else if(row.dataset.newUser&&!row.dataset.remove){
            await api(`/api/v1/access-lists/${id}/users/${encodeURIComponent(row.dataset.newUser)}`,{method:'PUT',body:JSON.stringify({password:row.dataset.password})});
          }
        }
        toast(x?'Access list updated':'Access list created'); await accessListsPage();
      }
    });
  const credentials=$('#access-credentials');
  credentials.querySelectorAll('.credential-remove').forEach(btn=>btn.onclick=()=>{const row=btn.closest('.credential-row');row.dataset.remove='1';row.classList.add('hidden')});
  $('#access-add-user').onclick=()=>{const user=$('#access-new-user').value.trim(),pass=$('#access-new-pass').value;if(!user)return $('#resource-error').textContent='Enter a username.';if(pass.length<8)return $('#resource-error').textContent='Password must be at least 8 characters.';if(Array.from($$('.credential-row')).some(r=>(r.dataset.existingUser||r.dataset.newUser)===user&&!r.dataset.remove))return $('#resource-error').textContent='This username already exists.';const row=document.createElement('div');row.className='credential-row';row.dataset.newUser=user;row.dataset.password=pass;row.innerHTML=`<div class="credential-user">${esc(user)}</div><div class="muted">New credential</div><button type="button" class="btn small danger credential-remove">Remove</button>`;row.querySelector('.credential-remove').onclick=()=>row.remove();credentials.appendChild(row);$('#access-new-user').value='';$('#access-new-pass').value='';$('#resource-error').textContent='';};
  return d;
}

async function migrationPage() {
  $('#content').innerHTML = `
    <div class="grid-2 migration-intro">
      <form id="migration-form" class="card">
        <div class="section-head"><div><h2>Connect to running installation</h2><p class="muted">The source is read only. Nothing is changed there.</p></div><span class="pill">Analyze first</span></div>
        <label>Source type<select id="migration-type" disabled><option>NGINX Proxy Manager</option></select></label>
        <label>URL<input id="migration-url" type="url" placeholder="http://192.168.1.20:81" required><small>Use the admin URL. ZentProxy automatically adds <span class="code">/api</span>.</small></label>
        <label>E-mail / identity<input id="migration-identity" autocomplete="username" placeholder="admin@example.com" required></label>
        <label>Password<input id="migration-secret" type="password" autocomplete="current-password" required></label>
        <label class="switch-row"><input id="migration-tls-skip" type="checkbox"><span>Allow self-signed TLS certificate</span><small>Only enable this for a source you control on a trusted network.</small></label>
        <div id="migration-error" class="error-text"></div>
        <div class="dialog-actions"><button id="migration-analyze" class="btn primary btn-icon" type="submit">${icon('search')}<span>Analyze installation</span></button></div>
      </form>
      <div class="card">
        <div class="section-head"><h2>Migration rules</h2></div>
        <div class="list">
          <div class="list-row"><span>Source changes</span><strong class="good-text">None</strong></div>
          <div class="list-row"><span>Credentials stored</span><strong class="good-text">No</strong></div>
          <div class="list-row"><span>Existing ZentProxy hosts</span><strong>Protected</strong></div>
          <div class="list-row"><span>Final activation</span><strong>Validated configuration</strong></div>
          <div class="list-row"><span>Activation failure</span><strong>Automatic rollback</strong></div>
        </div>
        <p class="muted mt16">Routing, TLS, HSTS, HTTP/2, caching, advanced configuration, custom locations, redirects, 404 hosts, streams and access lists are preserved. For lossless certificates and Basic Auth, mount the source data read-only at /migration/data and the source Let's Encrypt directory at /migration/letsencrypt.</p>
      </div>
    </div>
    <div id="migration-analysis" class="mt16"></div>`;

  $('#migration-form').onsubmit = async (e) => {
    e.preventDefault();
    const button = $('#migration-analyze');
    $('#migration-error').textContent = '';
    state.migrationCreds = {
      base_url: $('#migration-url').value.trim(), identity: $('#migration-identity').value.trim(),
      secret: $('#migration-secret').value, tls_skip_verify: $('#migration-tls-skip').checked,
    };
    button.disabled = true; button.textContent = 'Analyzing…';
    try {
      const analysis = await api('/api/v1/migration/analyze', { method: 'POST', body: JSON.stringify(state.migrationCreds) });
      renderMigrationAnalysis(obj(analysis));
    } catch (err) {
      $('#migration-error').textContent = err.message;
      $('#migration-analysis').innerHTML = '';
    } finally {
      button.disabled = false; button.textContent = 'Analyze installation';
    }
  };
}

function resourceCountText(r) { return num(r.count) < 0 ? 'Unknown' : fmtNum(r.count); }
function renderMigrationAnalysis(a) {
  const resources = arr(a.resources), plans = arr(a.proxy_hosts), certs = arr(a.certificates), source = obj(a.source);
  const blockers = resources.filter((r) => num(r.count) > 0 && !r.importable && r.key !== 'users');
  $('#migration-analysis').innerHTML = `
    <div class="card">
      <div class="section-head"><div><h2>Analysis</h2><p class="muted">${esc(source.url)}${source.version ? ` · version ${esc(source.version)}` : ''}</p></div><span class="pill good">Read only</span></div>
      <div class="migration-resource-grid">${resources.map((r) => `<div class="migration-resource"><span class="muted">${esc(r.label)}</span><strong>${resourceCountText(r)}</strong><small class="${r.importable ? 'good-text' : (num(r.count)>0 && r.key!=='users' ? 'warn-text' : '')}">${esc(r.note || '')}</small></div>`).join('')}</div>
      ${certs.length ? `<div class="mt16"><div class="section-head"><h2>Certificate migration</h2></div><div class="list">${certs.map(c=>{const status=c.reissue?'Reissue after migration':(c.importable?'Ready':esc(c.warning||'Needs certificate material'));const detail=c.reissue&&c.warning?`<small class="warn-text">${esc(c.warning)}</small>`:'';return `<div class="list-row"><span>${esc(c.name)} · ${esc(c.provider)}${detail}</span><strong class="${c.reissue?'warn-text':(c.importable?'good-text':'warn-text')}">${status}</strong></div>`;}).join('')}</div></div>` : ''}
      ${blockers.length ? `<div class="card danger-text mt16"><strong>Full migration is blocked until the required source material is available.</strong><div class="tiny mt8">${blockers.map((r)=>`<div>${esc(r.label)}: ${esc(r.note || 'not safely importable')}</div>`).join('')}</div></div>` : ''}
    </div>
    <div id="migration-import-error" class="migration-primary-error" role="alert" aria-live="assertive"></div>
    <div class="card mt16">
      <div class="section-head"><div><h2>Proxy hosts</h2><p class="muted">${fmtNum(a.importable_proxy_hosts)} ready · ${fmtNum(a.blocked_proxy_hosts)} blocked</p></div><div class="inline-actions"><button id="migration-select-all" class="btn small">Select ready</button><button id="migration-import" class="btn primary" ${blockers.length?'disabled':''}>Import migration</button></div></div>
      ${migrationPlanTable(plans)}
      <div id="migration-result"></div>
    </div>`;

  const selectAll = $('#migration-select-all');
  if (selectAll) selectAll.onclick = () => $$('[data-migration-host]:not(:disabled)').forEach((x) => { x.checked = true; });
  const importButton = $('#migration-import');
  if (importButton) importButton.onclick = async () => {
    if (state.migrationImporting) return;
    const ids = $$('[data-migration-host]:checked').map((x) => +x.value).filter((x) => x > 0);
    if (!ids.length && plans.length) { $('#migration-import-error').textContent = 'Select at least one ready proxy host.'; return; }
    if (!state.migrationCreds) { $('#migration-import-error').textContent = 'Run the analysis again before importing.'; return; }
    $('#migration-import-error').textContent = '';
    const hostText = ids.length ? `${ids.length} selected proxy host${ids.length === 1 ? '' : 's'}` : 'the detected routing configuration';
    if (!confirm(`Import ${hostText} plus compatible certificates, access lists, redirects, 404 hosts and streams into ZentProxy?`)) return;
    state.migrationImporting = true;
    importButton.disabled = true; importButton.setAttribute('aria-busy', 'true'); importButton.textContent = 'Importing…';
    if (selectAll) selectAll.disabled = true;
    try {
      const result = obj(await api('/api/v1/migration/import', { method: 'POST', body: JSON.stringify({ ...state.migrationCreds, source_ids: ids }) }));
      const certFailures = num(result.failed_certificates);
      $('#migration-result').innerHTML = `<div class="success-banner"><strong>${fmtNum(result.imported)} proxy hosts · ${fmtNum(result.imported_certificates)} certificates · ${fmtNum(result.imported_access_lists)} access lists · ${fmtNum(result.imported_redirect_hosts)} redirects · ${fmtNum(result.imported_dead_hosts)} 404 hosts · ${fmtNum(result.imported_streams)} streams imported.</strong>${certFailures ? `<div class="warn-text mt8"><strong>${fmtNum(certFailures)} certificate request${certFailures === 1 ? '' : 's'} failed. The remaining migration was completed.</strong></div>` : ''}${arr(result.warnings).length ? `<div class="tiny mt8">${arr(result.warnings).map((w) => `<div>${esc(w)}</div>`).join('')}</div>` : ''}<div class="mt8"><button id="migration-open-hosts" class="btn small">Open Proxy Hosts</button></div></div>`;
      $('#migration-open-hosts').onclick = () => loadPage('hosts');
      ids.forEach((id) => { const cb = $(`[data-migration-host][value="${id}"]`); if (cb) { cb.checked = false; cb.disabled = true; } });
      toast('Migration completed');
    } catch (err) {
      $('#migration-import-error').textContent = err.message;
    } finally {
      state.migrationImporting = false;
      importButton.removeAttribute('aria-busy'); importButton.disabled = blockers.length > 0; importButton.textContent = 'Import migration';
      if (selectAll) selectAll.disabled = false;
    }
  };
}

function migrationPlanTable(plans) {
  plans = arr(plans);
  if (!plans.length) return '<div class="empty">No proxy hosts found on the source installation.</div>';
  return `<div class="table-wrap"><table><thead><tr><th></th><th>Domains</th><th>Upstream</th><th>Status</th><th>Compatibility</th></tr></thead><tbody>${plans.map((p) => {
    const warnings = arr(p.warnings);
    const issue = p.conflict ? `<div class="danger-text tiny">${esc(p.conflict)}</div>` : warnings.map((w) => `<div class="warn-text tiny">${esc(w)}</div>`).join('');
    return `<tr><td><input class="table-check" data-migration-host type="checkbox" value="${p.source_id}" ${p.importable ? 'checked' : 'disabled'}></td><td>${arr(p.domains).map((d) => `<span class="pill">${esc(d)}</span>`).join(' ') || '<span class="muted">No domain</span>'}</td><td class="code">${esc(p.upstream)}</td><td>${p.enabled ? '<span class="pill good">Enabled</span>' : '<span class="pill">Disabled</span>'}</td><td>${p.importable ? '<span class="good-text">Ready</span>' : '<span class="danger-text">Blocked</span>'}${issue ? `<div class="migration-notes">${issue}</div>` : ''}</td></tr>`;
  }).join('')}</tbody></table></div>`;
}

async function developers() {
  const [keysRaw, capsRaw] = await Promise.all([api('/api/v1/api-keys'), api('/api/v1/system/capabilities')]);
  const keys = arr(keysRaw), caps = obj(capsRaw), scopes = arr(caps.api_key_scopes);
  $('#content').innerHTML = `<div class="grid-2"><div class="card">${sectionHeading('key', 'Create API key', `<span class="pill">${esc(caps.api_version)}</span>`)}<form id="key-form"><label>Name<input id="key-name" placeholder="home-assistant" required></label><div class="api-scope-grid">${scopes.map((s) => `<label><input type="checkbox" value="${esc(s)}">${esc(s)}</label>`).join('')}</div><div id="key-error" class="error-text"></div><div class="dialog-actions"><button class="btn primary btn-icon">${icon('add')}<span>Create key</span></button></div></form></div><div class="card">${sectionHeading('developer', 'Integration contract')}<p>Use <span class="code">Authorization: Bearer &lt;token&gt;</span>. Keys are independently scoped and revocable.</p><p><a class="good-text icon-link" href="/api/docs" target="_blank" rel="noopener">${icon('external')}<span>Open interactive API documentation</span></a></p><p class="tiny"><a class="muted" href="/api/v1/openapi.yaml" target="_blank" rel="noopener">View raw OpenAPI specification</a></p><div class="list"><div class="list-row"><span>Base path</span><strong class="code">/api/v1</strong></div><div class="list-row"><span>Authentication</span><strong>Bearer API key</strong></div><div class="list-row"><span>Format</span><strong>JSON</strong></div></div></div></div><div class="card mt16">${sectionHeading('key', 'API keys')}${apiKeyTable(keys)}</div>`;
  $('#key-form').onsubmit = async (e) => {
    e.preventDefault();
    const selectedScopes = $$('#key-form input[type=checkbox]:checked').map((x) => x.value);
    try {
      const d = obj(await api('/api/v1/api-keys', { method: 'POST', body: JSON.stringify({ name: $('#key-name').value, scopes: selectedScopes }) }));
      $('#token-value').textContent = d.token || '';
      $('#token-dialog').showModal();
      await developers();
    } catch (err) { $('#key-error').textContent = err.message; }
  };
  $$('[data-revoke-key]').forEach((b) => { b.onclick = async () => { if (!confirm('Revoke this API key?')) return; await api(`/api/v1/api-keys/${b.dataset.revokeKey}`, { method: 'DELETE' }); toast('API key revoked'); await developers(); }; });
}
function apiKeyTable(keys) {
  keys = arr(keys);
  if (!keys.length) return '<div class="empty">No API keys yet.</div>';
  return `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Prefix</th><th>Scopes</th><th>Last used</th><th>Status</th><th></th></tr></thead><tbody>${keys.map((k) => `<tr><td>${esc(k.name)}</td><td class="code">${esc(k.prefix)}…</td><td>${arr(k.scopes).map((s) => `<span class="pill">${esc(s)}</span>`).join(' ')}</td><td>${k.last_used ? new Date(k.last_used).toLocaleString() : 'Never'}</td><td>${k.revoked_at ? '<span class="danger-text">Revoked</span>' : '<span class="good-text">Active</span>'}</td><td>${k.revoked_at ? '' : `<button class="btn small danger" data-revoke-key="${k.id}">Revoke</button>`}</td></tr>`).join('')}</tbody></table></div>`;
}

$('[data-close-token]').onclick = () => $('#token-dialog').close();
$('#copy-token').onclick = async () => { await navigator.clipboard.writeText($('#token-value').textContent); toast('Token copied'); };

async function audit() {
  const rows = arr(await api('/api/v1/audit?limit=200'));
  if (!rows.length) { $('#content').innerHTML = emptyState('audit', 'No audit events yet.'); return; }
  $('#content').innerHTML = `<div class="table-wrap"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Object</th><th>Detail</th></tr></thead><tbody>${rows.map((x) => `<tr><td>${new Date(x.at).toLocaleString()}</td><td class="code">${esc(x.actor)}</td><td>${esc(x.action)}</td><td>${esc(x.object_type)} ${esc(x.object_id)}</td><td>${esc(x.detail)}</td></tr>`).join('')}</tbody></table></div>`;
}


function docLanguage() { return (window.ZentI18n && ZentI18n.language === 'de') ? 'de' : 'en'; }
function documentationPage() {
  const lang = docLanguage();
  const source = window.ZentDocs?.articles || [];
  const currentExists = source.some((a) => a.id === state.docsArticle);
  if (!currentExists && source.length) state.docsArticle = source[0].id;
  $('#content').innerHTML = `<div class="docs-shell">
    <aside class="card docs-sidebar">
      <label class="docs-search"><span class="docs-search-label"><span class="section-icon">${icon('search')}</span>${esc(tr('Documentation search'))}</span><input id="docs-search" type="search" placeholder="${esc(tr('Search documentation…'))}" autocomplete="off"></label>
      <div id="docs-list" class="docs-list"></div>
    </aside>
    <article id="docs-article" class="card docs-article"></article>
  </div>`;
  const renderList = () => {
    const q = ($('#docs-search').value || '').trim().toLowerCase();
    const matches = source.filter((raw) => {
      const a = ZentDocs.get(raw.id, lang);
      const hay = [a.title, a.summary, ...(a.sections || []).flatMap((s) => [s[0], ...(s[1] || []), ...(s[2] || [])])].join(' ').toLowerCase();
      return !q || hay.includes(q);
    });
    $('#docs-list').innerHTML = matches.length ? matches.map((raw) => {
      const a = ZentDocs.get(raw.id, lang);
      return `<button class="docs-item ${raw.id === state.docsArticle ? 'active' : ''}" data-doc-id="${esc(raw.id)}"><strong>${esc(a.title)}</strong><small>${esc(a.summary)}</small></button>`;
    }).join('') : `<div class="docs-empty">${esc(tr('No documentation found.'))}</div>`;
    $$('[data-doc-id]').forEach((b) => b.onclick = () => { state.docsArticle = b.dataset.docId; renderList(); renderArticle(); });
  };
  const renderArticle = () => {
    const a = ZentDocs.get(state.docsArticle, lang);
    if (!a) { $('#docs-article').innerHTML = `<div class="docs-empty">${esc(tr('No documentation found.'))}</div>`; return; }
    $('#docs-article').innerHTML = `<div class="docs-article-header"><div class="docs-title-row"><span class="docs-title-icon">${icon('documentation')}</span><h2>${esc(a.title)}</h2></div><p class="muted">${esc(a.summary)}</p><div class="docs-meta"><span class="pill">${esc(a.category)}</span><span class="pill good">${esc(tr('Updated with this ZentProxy version.'))}</span></div></div>
      ${(a.sections || []).map((sec) => `<section class="docs-section"><h3>${esc(sec[0])}</h3>${arr(sec[1]).map((p) => `<p>${esc(p)}</p>`).join('')}${arr(sec[2]).length ? `<ul>${arr(sec[2]).map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}</section>`).join('')}`;
  };
  $('#docs-search').addEventListener('input', renderList);
  renderList(); renderArticle();
}

async function persistLanguage(language) {
  if (!['de','en'].includes(language)) return;
  if (!state.me) {
    ZentI18n.setLanguage(language);
    location.reload();
    return;
  }
  try {
    await api('/api/v1/user/preferences/language', {method:'PUT', body:JSON.stringify({language})});
    localStorage.setItem('zentproxy.language', language);
    location.reload();
  } catch (err) { toast(err.message); }
}

$('#language-select').addEventListener('change', (e) => persistLanguage(e.target.value));
$('#login-language').addEventListener('change', (e) => { ZentI18n.setLanguage(e.target.value); location.reload(); });

init();
