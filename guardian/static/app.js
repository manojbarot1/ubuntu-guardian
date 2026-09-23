"use strict";
/* Guardian dashboard: Grafana-style panels rendered from the JSON API. No build step, no dependencies. */

// ------------------------------------------------------------------ helpers
const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const store = {
  get(k, d) { try { const v = localStorage.getItem("guardian-" + k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
  set(k, v) { try { localStorage.setItem("guardian-" + k, JSON.stringify(v)); } catch (e) { /* storage blocked */ } },
};
function bytes(n, d = 1) {
  if (n == null || isNaN(n)) return "–";
  const u = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]; let i = 0; n = Number(n);
  while (Math.abs(n) >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(Math.abs(n) >= 100 ? 0 : d) : Math.round(n)) + " " + u[i];
}
const bps = (n) => (n == null ? "–" : bytes(n) + "/s");
const pct = (n, d = 1) => (n == null || isNaN(n) ? "–" : Number(n).toFixed(d) + "%");
const num = (n) => (n == null ? "–" : Number(n).toLocaleString());
const fix = (d) => (n) => (n == null ? "–" : Number(n).toFixed(d));
const ago = (ts) => {
  if (!ts) return "never";
  const s = Date.now() / 1000 - (typeof ts === "string" ? Date.parse(ts) / 1000 : ts);
  if (s < 90) return Math.round(s) + "s ago";
  if (s < 5400) return Math.round(s / 60) + " min ago";
  if (s < 172800) return Math.round(s / 3600) + " h ago";
  return Math.round(s / 86400) + " days ago";
};
function uptime(s) {
  if (!s) return "–";
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d} day${d > 1 ? "s" : ""}, ${h}:${String(m).padStart(2, "0")}` : `${h}:${String(m).padStart(2, "0")} h`;
}
const last = (a) => { for (let i = a.length - 1; i >= 0; i--) if (a[i] != null) return a[i]; return null; };
const sum = (a) => a.reduce((x, y) => x + (y || 0), 0);
function toast(msg) {
  const t = document.createElement("div"); t.className = "toast"; t.textContent = msg;
  document.body.appendChild(t); setTimeout(() => t.remove(), 5000);
}
async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { "Content-Type": "application/json", "X-Guardian": "1", ...(opts.headers || {}) } });
  if (r.status === 401) { location.href = "/login"; throw new Error("login required"); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.detail || r.statusText);
  return j;
}
const post = (path, body) => api(path, { method: "POST", body: JSON.stringify(body || {}) });

// ------------------------------------------------------------------ colours & thresholds
const PAL = ["#73bf69", "#f2cc0c", "#8ab8ff", "#ff780a", "#f2495c", "#5794f2", "#b877d9", "#705da0", "#37872d", "#fade2a", "#1f78c1", "#e0b400"];
const pal = (i) => PAL[i % PAL.length];
const TH = {
  pct: [[0, "green"], [75, "orange"], [90, "red"]],
  pctSoft: [[0, "green"], [60, "orange"], [85, "red"]],
  iowait: [[0, "green"], [5, "orange"], [20, "red"]],
  zombie: [[0, "green"], [1, "orange"], [20, "red"]],
  temp: [[0, "green"], [55, "orange"], [70, "red"]],
  none: [[0, "green"]],
  blue: [[0, "cyan"]],
};
function thColor(v, th = TH.pct) {
  let c = th[0][1];
  for (const [t, col] of th) if (v != null && v >= t) c = col;
  return `var(--${c})`;
}

// ------------------------------------------------------------------ panel primitives
const cls = (o) => `p s${o.span || 6} ${o.h === "auto" ? "hauto" : o.h ? "h" + o.h : ""} ${o.cls || ""}`;
function panel(title, body, o = {}) {
  return `<div class="${cls(o)}">
    <div class="pt">${o.dot ? '<span class="dot"></span>' : ""}<span>${esc(title)}</span>${o.info ? `<span class="info" title="${esc(o.info)}">i</span>` : ""}${o.right ? `<span class="r">${o.right}</span>` : ""}</div>
    <div class="pb">${body}</div></div>`;
}
function spark(values, color, max) {
  const v = values.filter((x) => x != null);
  if (v.length < 2) return "";
  const hi = max ?? (Math.max(...v) * 1.15 || 1), lo = Math.min(0, ...v);
  const pts = values.map((x, i) => (x == null ? null : [(i / (values.length - 1)) * 100, 30 - ((x - lo) / (hi - lo || 1)) * 30])).filter(Boolean);
  const line = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(2) + "," + p[1].toFixed(2)).join("");
  return `<svg class="spark" viewBox="0 0 100 30" preserveAspectRatio="none" aria-hidden="true">
    <path d="${line}L100,30L0,30Z" fill="${color}" opacity=".18"/><path d="${line}" fill="none" stroke="${color}" stroke-width="1.2" vector-effect="non-scaling-stroke"/></svg>`;
}
function stat(o) {
  const color = o.color || thColor(o.raw ?? null, o.th || TH.none);
  const len = Math.max(4, String(o.value ?? "").length + (o.unit ? o.unit.length * 0.5 : 0));
  const val = `<div class="v" style="color:${color};--len:${len}">${esc(o.value)}${o.unit ? `<small>${esc(o.unit)}</small>` : ""}</div>`;
  return panel(o.title, `${o.spark ? spark(o.spark, color, o.sparkMax) : ""}${val}${o.sub ? `<div class="sub">${o.sub}</div>` : ""}`,
    { ...o, cls: `stat ${o.small ? "small" : ""} ${o.cls || ""}`, h: o.h || 2 });
}
function multi(o) {
  const items = o.items.map((it) => `<div class="it">${it.spark ? spark(it.spark, it.color || "var(--green)") : ""}
     <div class="l">${esc(it.label)}</div><div class="v" style="color:${it.color || "var(--green)"};--len:${Math.max(3, String(it.value).length)}">${esc(it.value)}</div></div>`).join("");
  return panel(o.title, items, { ...o, cls: "multi", h: o.h || 2 });
}
function polar(cx, cy, r, deg) { const a = (deg * Math.PI) / 180; return [cx + r * Math.sin(a), cy - r * Math.cos(a)]; }
function arc(cx, cy, r, a0, a1) {
  const [x0, y0] = polar(cx, cy, r, a0), [x1, y1] = polar(cx, cy, r, a1);
  return `M${x0.toFixed(2)},${y0.toFixed(2)}A${r},${r} 0 ${a1 - a0 > 180 ? 1 : 0} 1 ${x1.toFixed(2)},${y1.toFixed(2)}`;
}
function gauge(o) {
  const min = o.min ?? 0, max = o.max ?? 100, th = o.th || TH.pct;
  const v = o.value == null || isNaN(o.value) ? null : Number(o.value);
  const f = v == null ? 0 : Math.max(0, Math.min(1, (v - min) / (max - min || 1)));
  const A0 = -120, A1 = 120, span = A1 - A0, color = v == null ? "var(--faint)" : thColor(v, th);
  // Outer threshold band (as in Grafana), then the value arc on a track.
  let band = "";
  th.forEach(([t, c], i) => {
    const s = A0 + Math.max(0, Math.min(1, (t - min) / (max - min))) * span;
    const e = i + 1 < th.length ? A0 + Math.max(0, Math.min(1, (th[i + 1][0] - min) / (max - min))) * span : A1;
    if (e > s) band += `<path d="${arc(100, 92, 88, s, e)}" stroke="var(--${c})" stroke-width="4" fill="none"/>`;
  });
  const valTxt = v == null ? "–" : (o.fmt ? o.fmt(v) : pct(v));
  const fs = valTxt.length > 9 ? 19 : valTxt.length > 7 ? 23 : 30;
  const svg = `<svg viewBox="0 0 200 150" preserveAspectRatio="xMidYMid meet" role="img" aria-label="${esc(o.title)} ${esc(valTxt)}">
    ${band}<path d="${arc(100, 92, 72, A0, A1)}" stroke="var(--track)" stroke-width="18" fill="none"/>
    ${f > 0.002 ? `<path d="${arc(100, 92, 72, A0, A0 + f * span)}" stroke="${color}" stroke-width="18" fill="none"/>` : ""}
    <text class="gv" x="100" y="104" text-anchor="middle" font-size="${fs}" fill="${color}">${esc(valTxt)}</text>
    ${o.sub ? `<text class="gsub" x="100" y="142" text-anchor="middle">${esc(o.sub)}</text>` : ""}</svg>`;
  return panel(o.title, svg, { ...o, cls: "gauge", h: o.h || 3 });
}
function barGauge(rows, o = {}) {
  const max = o.max ?? Math.max(1, ...rows.map((r) => r.value || 0));
  return rows.map((r, i) => {
    const f = Math.max(0, Math.min(1, (r.value || 0) / max));
    const c = r.color || pal(i + 2);
    return `<div class="bg-row"><span class="n" title="${esc(r.name)}">${esc(r.name)}</span><span class="t"><i style="width:${(f * 100).toFixed(1)}%;background:${c}"></i></span><span class="val" style="color:${c}">${esc(o.fmt ? o.fmt(r.value) : r.value)}</span></div>`;
  }).join("");
}

// ------------------------------------------------------------------ time series
const charts = new Map();
let chartSeq = 0;
function niceMax(v) {
  if (!(v > 0)) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v))), n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p;
}
function tlabel(t, span) {
  const d = new Date(t * 1000);
  return span > 2 * 86400 ? `${d.getMonth() + 1}/${d.getDate()}` : d.toTimeString().slice(0, 5);
}
function timeseries(o) {
  const key = o.key || o.title, hidden = state.hidden[key] || [];
  const t = o.t || [];
  const vis = o.series.filter((s) => !hidden.includes(s.name));
  const fmt = o.fmt || fix(1);
  if (t.length < 2 || !o.series.length) return panel(o.title, `<div class="empty">No data in this time range yet</div>`, { ...o, cls: "ts", h: o.h || 4 });
  const all = vis.flatMap((s) => s.values).filter((v) => v != null);
  const lo = o.min ?? 0, hi = o.max ?? niceMax((all.length ? Math.max(...all) : 1) * 1.05);
  const t0 = t[0], t1 = t[t.length - 1], W = 1000, H = 300, gap = o.gap || (state.step || 15) * 3.5;
  const X = (x) => ((x - t0) / (t1 - t0 || 1)) * W;
  const Y = (v) => H - ((Math.min(Math.max(v, lo), hi) - lo) / (hi - lo || 1)) * H;
  let body = "";
  for (let k = 1; k < 4; k++) body += `<line class="gl" x1="0" x2="${W}" y1="${(H * k) / 4}" y2="${(H * k) / 4}" vector-effect="non-scaling-stroke"/>`;
  vis.forEach((s) => {
    if (o.bars) {
      const bw = (W / t.length) * 0.75;
      s.values.forEach((v, i) => { if (v != null) body += `<rect x="${(X(t[i]) - bw / 2).toFixed(1)}" y="${Y(v).toFixed(1)}" width="${bw.toFixed(1)}" height="${(H - Y(v)).toFixed(1)}" fill="${s.color}" opacity=".75"/>`; });
      return;
    }
    const segs = []; let cur = null;
    s.values.forEach((v, i) => {
      if (v == null || (cur && t[i] - t[i - 1] > gap)) { if (cur) segs.push(cur); cur = null; }
      if (v != null) { cur = cur || []; cur.push([X(t[i]), Y(v)]); }
    });
    if (cur) segs.push(cur);
    for (const sg of segs) {
      const d = sg.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + "," + p[1].toFixed(1)).join("");
      if (o.fill !== false) body += `<path d="${d}L${sg[sg.length - 1][0].toFixed(1)},${H}L${sg[0][0].toFixed(1)},${H}Z" fill="${s.color}" opacity=".08"/>`;
      body += `<path d="${d}" fill="none" stroke="${s.color}" stroke-width="1.6" vector-effect="non-scaling-stroke" stroke-linejoin="round"/>`;
    }
  });
  const ylabs = [0, 1, 2, 3, 4].map((k) => `<span class="yl" style="top:${100 - k * 25}%">${esc(fmt(lo + ((hi - lo) * k) / 4))}</span>`).join("");
  const xlabs = [0, 1, 2, 3, 4].map((k) => `<span class="xl" style="left:${k * 25}%">${tlabel(t0 + ((t1 - t0) * k) / 4, t1 - t0)}</span>`).join("");
  const id = "c" + ++chartSeq;
  charts.set(id, { t, series: vis, fmt });
  const calcs = o.calcs || ["max", "avg", "current"];
  let legend = "";
  if (o.legend !== "none") {
    if (o.legend === "list") {
      legend = `<div class="lg list">${o.series.map((s) => `<span data-toggle="${esc(key)}" data-name="${esc(s.name)}" style="${hidden.includes(s.name) ? "opacity:.35" : ""}"><i class="sw" style="background:${s.color}"></i>${esc(s.name)}</span>`).join("")}</div>`;
    } else {
      const rows = o.series.map((s) => {
        const v = s.values.filter((x) => x != null);
        const c = { min: v.length ? Math.min(...v) : null, max: v.length ? Math.max(...v) : null, avg: v.length ? sum(v) / v.length : null, current: last(s.values) };
        return `<tr class="${hidden.includes(s.name) ? "off" : ""}" data-toggle="${esc(key)}" data-name="${esc(s.name)}"><td><i class="sw" style="background:${s.color}"></i> ${esc(s.name)}</td>${calcs.map((k) => `<td>${esc(fmt(c[k]))}</td>`).join("")}</tr>`;
      }).join("");
      legend = `<div class="lg"><table><tr><th></th>${calcs.map((k) => `<th>${k}</th>`).join("")}</tr>${rows}</table></div>`;
    }
  }
  const plot = `<div class="plot"><div class="area" data-chart="${id}">
      <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" aria-hidden="true">${body}</svg>
      ${ylabs}${xlabs}<div class="xhl"></div><div class="tip"></div></div></div>`;
  const h = o.h || (o.legend === "right" || o.legend === "list" || o.legend === "none" ? 4 : 5);
  return panel(o.title, plot + legend, { ...o, cls: `ts legend-${o.legend === "right" ? "right" : "bottom"}`, h });
}
// Hover crosshair + tooltip for every chart (one delegated listener).
document.addEventListener("mousemove", (e) => {
  const area = e.target.closest?.(".area[data-chart]");
  document.querySelectorAll(".area.hot").forEach((a) => { if (a !== area) a.classList.remove("hot"); });
  if (!area) return;
  const c = charts.get(area.dataset.chart); if (!c) return;
  const r = area.getBoundingClientRect(), fx = (e.clientX - r.left) / r.width;
  const tt = c.t[0] + fx * (c.t[c.t.length - 1] - c.t[0]);
  let i = 0, best = Infinity;
  c.t.forEach((x, k) => { const d = Math.abs(x - tt); if (d < best) { best = d; i = k; } });
  area.classList.add("hot");
  const line = $(".xhl", area), tip = $(".tip", area);
  const px = ((c.t[i] - c.t[0]) / (c.t[c.t.length - 1] - c.t[0] || 1)) * r.width;
  line.style.left = px + "px";
  tip.innerHTML = `<div class="tt">${new Date(c.t[i] * 1000).toLocaleString()}</div>` +
    c.series.map((s) => `<div><i class="sw" style="background:${s.color}"></i>${esc(s.name)}<b>${esc(c.fmt(s.values[i]))}</b></div>`).join("");
  tip.style.left = (px > r.width * 0.6 ? px - tip.offsetWidth - 12 : px + 12) + "px";
  tip.style.top = Math.max(0, e.clientY - r.top - 20) + "px";
});
document.addEventListener("click", (e) => {
  const tg = e.target.closest("[data-toggle]");
  if (!tg) return;
  const key = tg.dataset.toggle, name = tg.dataset.name, h = new Set(state.hidden[key] || []);
  h.has(name) ? h.delete(name) : h.add(name);
  state.hidden[key] = [...h];
  render(false);
});

// Pivot rows [{ts, <key>, col...}] into aligned series.
function pivot(rows, key, col, names) {
  const t = [...new Set(rows.map((r) => r.ts))].sort((a, b) => a - b);
  const idx = new Map(t.map((x, i) => [x, i]));
  const by = new Map();
  for (const r of rows) {
    if (names && !names.includes(r[key])) continue;
    if (!by.has(r[key])) by.set(r[key], new Array(t.length).fill(null));
    by.get(r[key])[idx.get(r.ts)] = r[col];
  }
  return { t, by };
}
const colOf = (rows, c) => rows.map((r) => r[c]);

// ------------------------------------------------------------------ rows
function row(id, title, content, count) {
  const col = state.collapsed.includes(id);
  return `<div class="row-h ${col ? "collapsed" : ""}" data-row="${esc(id)}" role="button" tabindex="0" aria-expanded="${!col}">
    <svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg>${esc(title)}
    <span class="cnt">(${count ?? ""} panels)</span></div><div class="g">${content}</div>`;
}
document.addEventListener("click", (e) => {
  const h = e.target.closest("[data-row]"); if (!h) return;
  const id = h.dataset.row, set = new Set(state.collapsed);
  set.has(id) ? set.delete(id) : set.add(id);
  state.collapsed = [...set]; store.set("collapsed", state.collapsed);
  h.classList.toggle("collapsed"); h.setAttribute("aria-expanded", String(!set.has(id)));
});
const countPanels = (html) => (html.match(/class="p s/g) || []).length;
const R = (id, title, html) => row(id, title, html, countPanels(html));

// ------------------------------------------------------------------ actions (preview -> confirm -> execute)
const dlg = $("#action");
let pending = null;
const chip = (c, text) => `<span class="chip ${esc(c)}">${esc(text)}</span>`;
async function act(req) {
  let plan;
  try { plan = await post("/api/actions/preview", req); } catch (e) { toast(e.message); return; }
  pending = plan;
  $("#a-title").textContent = plan.summary;
  const pre = (plan.preconditions || []).map((p) =>
    `<li>${p.ok ? "✅" : p.blocking === false ? "⚠️" : "⛔"} <b>${esc(p.check)}</b>${p.ok ? "" : " — " + esc(p.detail)}</li>`).join("");
  $("#a-body").innerHTML = `
    <p>${esc(plan.impact)}</p>
    <div class="kv"><div>Risk</div><div>${chip(plan.risk === "high" ? "warn" : plan.risk === "critical" ? "crit" : "info", plan.risk || "–")}</div>
    <div>Current state</div><div class="mono">${esc(JSON.stringify(plan.before))}</div>
    <div>Rollback</div><div>${esc(plan.rollback)}</div></div>
    ${pre ? `<ul class="pre">${pre}</ul>` : ""}
    ${plan.confirm.level === "type" && plan.token ? `<p>Type <b class="mono">${esc(plan.confirm.text)}</b> to confirm:</p><input class="in" type="text" id="a-confirm" autocomplete="off">` : ""}
    ${plan.token ? "" : `<p style="color:var(--red)"><b>Blocked:</b> fix the ⛔ items first.</p>`}`;
  $("#a-go").disabled = !plan.token;
  $("#a-go").className = "btn " + (plan.risk === "high" || plan.type === "purge" ? "danger" : "primary");
  dlg.showModal();
}
$("#a-cancel").onclick = () => dlg.close();
$("#a-go").onclick = async () => {
  if (!pending?.token) return;
  $("#a-go").disabled = true;
  try {
    const r = await post("/api/actions/execute", { token: pending.token, confirm: $("#a-confirm")?.value || "" });
    dlg.close(); toast(`${pending.summary}: ${r.status} (audit #${r.audit_id})`); render(true);
  } catch (e) { toast(e.message); $("#a-go").disabled = false; }
};
document.addEventListener("click", (e) => { const b = e.target.closest("[data-act]"); if (b) { e.preventDefault(); act(JSON.parse(b.dataset.act)); } });
const actBtn = (label, req, c = "sm") => `<button class="btn ${c}" data-act='${esc(JSON.stringify(req))}'>${esc(label)}</button>`;

// ------------------------------------------------------------------ state, sidebar, top bar
const state = {
  range: store.get("range", "1h"), every: store.get("every", 15), collapsed: store.get("collapsed", ["procs"]),
  hidden: {}, step: 15, page: null, arg: null, vars: store.get("vars", {}),
};
const I = (d) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
const NAV = [
  ["server", "Server", I('<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>')],
  ["docker", "Docker containers", I('<path d="M3 7.5 12 3l9 4.5v9L12 21l-9-4.5z"/><path d="m3 7.5 9 4.5 9-4.5M12 12v9"/>')],
  ["immich", "Immich", I('<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="2"/><path d="m21 17-5-5-9 8"/>')],
  ["storage", "Storage", I('<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>')],
  ["services", "Services", I('<path d="M12 2 2 7l10 5 10-5-10-5z"/><path d="m2 17 10 5 10-5M2 12l10 5 10-5"/>')],
  ["network", "Network", I('<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18"/>')],
  ["duplicates", "Duplicate files", I('<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>')],
  ["security", "Security", I('<path d="M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3z"/><path d="m9 12 2 2 4-4"/>')],
  ["alerts", "Recommendations", I('<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.9 1.9 0 0 0 3.4 0"/>')],
  ["audit", "Audit log", I('<rect x="5" y="4" width="14" height="17" rx="2"/><path d="M9 4V3h6v1M9 11h6M9 15h4"/>')],
  ["settings", "Settings", I('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>')],
];
$("#side").innerHTML = `<img class="logo" src="/static/logo.svg" alt="Guardian">` +
  NAV.map(([id, label, icon]) => `<a href="#/${id}" data-nav="${id}" aria-label="${label}">${icon}<span class="tip">${label}</span></a>`).join("") +
  `<span class="spacer"></span><a href="#" id="logout" aria-label="Log out">${I('<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>')}<span class="tip">Log out</span></a>`;
$("#logout").onclick = async (e) => { e.preventDefault(); await post("/api/logout"); location.href = "/login"; };
const SUN = I('<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>');
const MOON = I('<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>');
const setThemeIcon = () => { $("#theme").innerHTML = document.documentElement.dataset.theme === "light" ? MOON : SUN; };
setThemeIcon();
$("#theme").onclick = () => {
  const t = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("guardian-theme", t); } catch (e) { /* storage blocked */ }
  setThemeIcon();
};
$("#range").value = state.range;
$("#every").value = String(state.every);
$("#range").onchange = (e) => { state.range = e.target.value; store.set("range", state.range); render(true); };
$("#every").onchange = (e) => { state.every = +e.target.value; store.set("every", state.every); schedule(); };
$("#refresh").onclick = () => render(true);

// ------------------------------------------------------------------ dashboards
const D = {};
const metrics = () => api("/api/metrics?range=" + state.range).then((m) => { state.step = m.step; return m; });
const checkValue = (c) => (c.ok ? String(c.code) : c.code ? String(c.code) : c.error || "Down");

D.server = {
  title: "Server stats", live: true,
  async render() {
    const [o, m, pr, recs] = await Promise.all([api("/api/overview"), metrics(), api("/api/processes"), api("/api/recommendations")]);
    const L = o.live.data || {}, S = m.samples, t = colOf(S, "ts"), P = m.procs, pd = pr.data || {};
    const ncpu = L.ncpu || 1, load = L.load || [0, 0, 0];
    const rxMax = niceMax(Math.max(65536, ...colOf(S, "net_rx_bps").filter(Boolean)) * 1.1);
    const txMax = niceMax(Math.max(65536, ...colOf(S, "net_tx_bps").filter(Boolean)) * 1.1);
    const swapFree = (L.swap?.total || 0) - (L.swap?.used || 0);
    const general =
      stat({ title: "Uptime", value: uptime(L.uptime), span: 3, dot: true, color: "var(--green)" }) +
      gauge({ title: "CPU usage", value: L.cpu, span: 3, h: 2 }) +
      stat({ title: "Load average (5m)", value: fix(2)(load[1]), raw: load[1], th: [[0, "green"], [ncpu * 0.7, "orange"], [ncpu, "red"]], spark: colOf(S, "load1"), span: 3, dot: true, info: "1, 5 and 15 minute run-queue averages", sub: `1m ${fix(2)(load[0])} · 15m ${fix(2)(load[2])}` }) +
      stat({ title: "IOWait", value: pct(L.cpu_split?.iowait, 2), raw: L.cpu_split?.iowait, th: TH.iowait, spark: colOf(S, "iowait"), span: 3, dot: true }) +
      multi({ title: "RAM", span: 3, dot: true, items: [
        { label: "total", value: bytes(L.mem?.total), color: "var(--green)" },
        { label: "used", value: bytes(L.mem?.used), color: thColor(L.mem?.percent, TH.pctSoft), spark: colOf(S, "mem_used") }] }) +
      gauge({ title: "RAM percentage", value: L.mem?.percent, span: 3, h: 2, dot: true }) +
      stat({ title: "Free swap", value: L.swap?.total ? bytes(swapFree) : "No swap", color: "var(--green)", spark: colOf(S, "swap_used"), span: 3, dot: true }) +
      gauge({ title: "Swap usage", value: L.swap?.total ? L.swap.percent : null, span: 3, h: 2 }) +
      stat({ title: "Users", value: num(o.processes.users), color: "var(--green)", spark: colOf(P, "users"), span: 2 }) +
      stat({ title: "Zombies", value: num(o.processes.zombies), raw: o.processes.zombies, th: TH.zombie, spark: colOf(P, "zombies"), span: 2 }) +
      stat({ title: "CPUs", value: ncpu, color: "var(--strong)", span: 2, info: "Logical CPUs (threads)" }) +
      stat({ title: "Processes", value: num(o.processes.count), color: "var(--green)", spark: colOf(P, "procs"), span: 3, dot: true }) +
      stat({ title: "Threads", value: num(o.processes.threads), color: "var(--green)", spark: colOf(P, "threads"), span: 3, dot: true }) +
      multi({ title: "Network connections", span: 6, dot: true, items: [
        { label: "tcp_established", value: num(L.tcp?.established), spark: colOf(S, "tcp_estab") },
        { label: "tcp_listen", value: num(L.tcp?.listen), spark: colOf(S, "tcp_listen") },
        { label: "tcp_time_wait", value: num(L.tcp?.time_wait), color: (L.tcp?.time_wait || 0) > 500 ? "var(--orange)" : "var(--green)", spark: colOf(S, "tcp_tw") },
        { label: "udp_socket", value: num(L.tcp?.udp), spark: colOf(S, "udp") }] }) +
      gauge({ title: "Download", value: L.net?.rx_bps, max: rxMax, fmt: bps, th: [[0, "green"], [rxMax * 0.7, "orange"], [rxMax * 0.9, "red"]], span: 3, h: 2, info: "Scale adapts to the peak in the selected range" }) +
      gauge({ title: "Upload", value: L.net?.tx_bps, max: txMax, fmt: bps, th: [[0, "green"], [txMax * 0.7, "orange"], [txMax * 0.9, "red"]], span: 3, h: 2 });

    const fs = o.storage || [];
    const nG = fs.length + fs.filter((f) => f.inodes_pct != null).length;
    const w = Math.max(4, Math.floor(24 / Math.max(1, nG)));
    const disks = fs.map((f) => gauge({ title: `Used (${f.mount})`, value: f.percent, sub: `${bytes(f.used)} of ${bytes(f.total)}`, span: w, h: 3 }) +
      (f.inodes_pct != null ? gauge({ title: `Inodes (${f.mount})`, value: f.inodes_pct, fmt: (v) => pct(v, 2), span: w, h: 3 }) : "")).join("");

    const lat = pivot(m.checks, "name", "ms").by;
    const checks = (o.checks || []).map((c) => stat({ title: c.name, value: checkValue(c), color: c.ok ? "var(--green)" : "var(--red)", spark: lat.get(c.name) || [], span: 3, dot: true, sub: `${c.ms} ms`, info: c.url })).join("");
    const b = o.backup.data || {}, lastB = b.last || {};
    const bAge = lastB.finished ? (Date.now() - Date.parse(lastB.finished)) / 86400000 : null;
    const imm = o.immich || {};
    const health = checks +
      stat({ title: "Immich", value: imm.reachable ? "Online" : "Offline", color: imm.reachable ? "var(--green)" : "var(--red)", span: 3, sub: `v${esc(imm.version || "?")} · ${imm.busy ? "processing" : "idle"}` }) +
      (b.enabled ? stat({ title: "Last backup", value: b.running ? "Running" : lastB.finished ? ago(lastB.finished) : "Never", color: b.running ? "var(--cyan)" : lastB.result === "failed" || bAge == null || bAge > 8 ? "var(--red)" : lastB.result === "warning" ? "var(--orange)" : "var(--green)", span: 3, small: true, sub: `next ${esc(b.timer?.NextElapseUSecRealtime || "not scheduled")}` }) : "") +
      (o.smart || []).map((d) => {
        const bad = d.failing || (d.warning || []).length;
        return stat({ title: d.model || "Drive", value: d.temp_c ? d.temp_c.toFixed(0) : (bad ? "FAIL" : "n/a"), unit: d.temp_c ? "°C" : "", raw: d.temp_c, th: TH.temp, color: bad ? "var(--red)" : d.temp_c ? undefined : "var(--muted)", span: 3, small: true, sub: bad ? "SMART failing" : d.temp_c ? "SMART healthy" : "no SMART data" });
      }).join("") +
      stat({ title: "Guardian overhead", value: pct(L.self?.cpu), raw: L.self?.cpu, th: [[0, "green"], [3, "orange"], [10, "red"]], spark: colOf(S, "self_cpu"), span: 3, sub: `${bytes(L.self?.rss)} RAM · ${L.busy ? "system busy" : "system idle"}` });
    const annotations = panel("Recommendations", `<div class="scroll">${recs.map(annRow).join("") || '<div class="empty">Nothing needs attention</div>'}</div>`, { span: 12, h: 5, right: `<a href="#/alerts">all →</a>` });
    const topCpu = panel("Top processes (CPU, last minute)", `<div class="scroll">${procTable(pd.top_cpu || [])}</div>`, { span: 12, h: 5 });

    const cpuTs = timeseries({ title: "CPU usage", t, fmt: (v) => pct(v), max: 100, span: 12, series: [
      { name: "user", color: pal(0), values: colOf(S, "cpu_user") }, { name: "system", color: pal(1), values: colOf(S, "cpu_system") },
      { name: "iowait", color: pal(4), values: colOf(S, "iowait") }] });
    const loadTs = timeseries({ title: "Load average", t, fmt: fix(2), span: 12, series: [{ name: "load 1m", color: pal(2), values: colOf(S, "load1") }] });
    const psiTs = timeseries({ title: "Pressure stall (PSI)", t, fmt: (v) => pct(v, 2), span: 12, info: "Share of time tasks waited for CPU, memory or I/O", series: [
      { name: "cpu", color: pal(0), values: colOf(S, "psi_cpu") }, { name: "memory", color: pal(3), values: colOf(S, "psi_mem") }, { name: "io", color: pal(6), values: colOf(S, "psi_io") }] });
    const memTs = timeseries({ title: "Memory", t, fmt: bytes, span: 12, series: [
      { name: "used", color: pal(1), values: colOf(S, "mem_used") }, { name: "swap used", color: pal(4), values: colOf(S, "swap_used") }] });

    let perCpu;
    if (m.cores.length) {
      const u = pivot(m.cores, "core", "user"), sy = pivot(m.cores, "core", "system"), io = pivot(m.cores, "core", "iowait");
      perCpu = [...u.by.keys()].sort((a, b) => a - b).map((c) => timeseries({ title: `CPU usage for cpu${c}`, key: "cpu" + c, t: u.t, fmt: (v) => pct(v), max: 100, span: 6,
        series: [{ name: `cpu${c} user`, color: pal(0), values: u.by.get(c) }, { name: `cpu${c} system`, color: pal(1), values: sy.by.get(c) }, { name: `cpu${c} iowait`, color: pal(4), values: io.by.get(c) }] })).join("");
    } else perCpu = panel("Per-CPU usage", '<div class="empty">Per-core history is kept for 48 hours. Pick a shorter time range.</div>', { span: 24, h: 2 });

    const io = timeseries({ title: "Disk I/O", t, fmt: bps, span: 12, series: [
      { name: "read", color: pal(2), values: colOf(S, "disk_read_bps") }, { name: "write", color: pal(3), values: colOf(S, "disk_write_bps") }] }) +
      timeseries({ title: "Network traffic", t, fmt: bps, span: 12, series: [
        { name: "download", color: pal(0), values: colOf(S, "net_rx_bps") }, { name: "upload", color: pal(1), values: colOf(S, "net_tx_bps") }] }) +
      timeseries({ title: "TCP connections", t, fmt: fix(0), span: 12, series: [
        { name: "established", color: pal(0), values: colOf(S, "tcp_estab") }, { name: "listen", color: pal(2), values: colOf(S, "tcp_listen") },
        { name: "time_wait", color: pal(3), values: colOf(S, "tcp_tw") }] }) +
      timeseries({ title: "Guardian's own CPU", t, fmt: (v) => pct(v), span: 12, info: "CPU used by Guardian itself (% of one core)", series: [{ name: "guardian", color: pal(6), values: colOf(S, "self_cpu") }] });

    const procs = panel("Top processes (memory)", `<div class="scroll">${procTable(pd.top_mem || [])}</div>`, { span: 12, h: 5 }) +
      panel("Applications (grouped)", `<div class="scroll"><table class="t"><tr><th>Application</th><th class="n">Procs</th><th class="n">CPU</th><th class="n">Memory</th></tr>
        ${(pd.apps || []).map((a) => `<tr><td>${esc(a.name)}</td><td class="n">${a.count}</td><td class="n">${a.cpu.toFixed(1)}%</td><td class="n">${bytes(a.rss)}</td></tr>`).join("")}</table></div>`, { span: 12, h: 5 });

    return R("general", `General - ${o.inventory?.hostname || "server"}`, general) + R("disks", "Disk usage", disks) +
      R("health", "Health & alerts", health + annotations + topCpu) + R("cpu", "CPU & memory", cpuTs + loadTs + psiTs + memTs) +
      R("percpu", "Per-CPU usage", perCpu) + R("io", "Disk & network I/O", io) + R("procs", "Processes", procs);
  },
};
function procTable(list) {
  return `<table class="t"><tr><th class="n">PID</th><th>Name</th><th>User</th><th class="n">CPU</th><th class="n">Memory</th><th>Command</th></tr>
    ${list.map((x) => `<tr><td class="n">${x.pid}</td><td>${esc(x.name)}</td><td class="muted">${esc(x.user)}</td><td class="n" style="color:${thColor(x.cpu, TH.pct)}">${x.cpu.toFixed(1)}%</td><td class="n">${bytes(x.rss)}</td><td class="mono muted">${esc(x.cmd)}</td></tr>`).join("")}</table>`;
}
function recTool(a) {
  if (a?.type === "backup_run") return actBtn("Run backup", { type: "backup_run" });
  if (a?.type === "security") return `<a class="btn sm" href="#/security" style="display:inline-flex;align-items:center">Security</a>`;
  if (a?.type === "service_detail") return `<a class="btn sm" href="#/services/${encodeURIComponent(a.target)}" style="display:inline-flex;align-items:center">Open</a>`;
  if (a?.type?.startsWith("container_")) { const v = a.type.split("_")[1]; return actBtn(`${v} ${a.target}`, { type: "container", verb: v, target: a.target }); }
  return "";
}
const annRow = (r) => `<div class="ann ${esc(r.severity)}"><span class="bar"></span><div class="body"><div class="ttl">${esc(r.title)}</div>
    <div class="d">${esc(r.detail)}</div></div><div class="tools">${chip(r.severity, r.severity)} ${chip("blue", r.category)} ${recTool(r.action)}</div></div>`;

D.docker = {
  title: "Docker containers", live: true,
  vars: () => ({ container: { label: "container", options: ["All", ...(state.containerNames || [])] } }),
  async render() {
    const [d, m, o] = await Promise.all([api("/api/docker"), metrics(), api("/api/overview")]);
    const inv = d.inventory.data || {}, live = (d.live.data || {}).containers || [], L = o.live.data || {};
    state.containerNames = (inv.containers || []).map((c) => c.name);
    const pick = state.vars.container && state.vars.container !== "All" ? [state.vars.container] : null;
    const cpuSum = sum(live.map((c) => c.cpu)), memSum = sum(live.map((c) => c.mem));
    const root = (o.storage || []).find((f) => f.mount === "/") || {};
    const imgSize = sum((inv.images || []).map((i) => i.size));
    const running = live.length, total = o.containers_total || (inv.containers || []).length;
    const series = (col) => { const p = pivot(m.containers, "name", col, pick); return { t: p.t, series: [...p.by.entries()].map(([n, v], i) => ({ name: n, color: pal(i), values: v })) }; };
    const count = pivot(m.containers, "name", "cpu");
    const runT = count.t.map((_, i) => [...count.by.values()].filter((v) => v[i] != null).length);
    const blk = pivot(m.containers, "name", "blk_r", pick), blkW = pivot(m.containers, "name", "blk_w", pick);
    const ioR = blk.t.map((_, i) => sum([...blk.by.values()].map((v) => v[i]))), ioW = blkW.t.map((_, i) => sum([...blkW.by.values()].map((v) => v[i])));
    const top = gauge({ title: "CPU load", value: (cpuSum / (ncpuOf(L) * 100)) * 100, fmt: (v) => pct(v, 2), span: 4, h: 3, info: "All running containers, share of total CPU" }) +
      stat({ title: "CPU cores", value: ncpuOf(L), color: "var(--strong)", span: 4, h: 3 }) +
      gauge({ title: "Memory load", value: (memSum / (L.mem?.total || 1)) * 100, span: 4, h: 3, info: "Container memory (excluding page cache) / total RAM" }) +
      stat({ title: "Used memory", value: bytes(memSum), color: "var(--green)", span: 4, h: 3 }) +
      gauge({ title: "Storage load", value: root.percent, span: 4, h: 3, info: "Root filesystem (Docker data lives here)" }) +
      stat({ title: "Containers", value: `${running}/${total}`, color: "var(--green)", span: 4, h: 3, sub: `running · ${(inv.images || []).length} images, ${bytes(imgSize)}` });
    const mid = timeseries({ title: "Running containers", t: count.t, bars: true, fmt: fix(0), span: 8, h: 3, legend: "none", series: [{ name: "running", color: "#7eb26d", values: runT }] }) +
      timeseries({ title: "System load", t: colOf(m.samples, "ts"), fmt: fix(2), span: 8, h: 3, legend: "none", series: [{ name: "load 1m", color: "#e24d42", values: colOf(m.samples, "load1") }] }) +
      timeseries({ title: "I/O usage (containers)", t: blk.t, fmt: bps, span: 8, h: 3, legend: "list", series: [{ name: "read", color: pal(2), values: ioR }, { name: "write", color: pal(3), values: ioW }] });
    const big = (title, col, fmt, info) => { const s = series(col); return timeseries({ title, key: "dk-" + col, t: s.t, series: s.series, fmt, span: 24, h: 4, legend: "right", calcs: ["min", "max", "avg"], info }); };
    const graphs = big("Container CPU usage", "cpu", (v) => pct(v, 2), "% of one core") + big("Container memory usage", "mem", bytes) +
      big("Container cached memory", "cache", bytes) + big("Container network input", "net_rx", bps) + big("Container network output", "net_tx", bps) +
      big("Container disk writes", "blk_w", bps);
    const byName = Object.fromEntries(live.map((c) => [c.name, c]));
    const rows = (inv.containers || []).filter((c) => !pick || pick.includes(c.name)).map((c) => {
      const l = byName[c.name] || {};
      const verbs = c.state === "running" ? ["restart", "stop"] : ["start"];
      return `<tr><td><b>${esc(c.name)}</b><div class="muted small">${esc(c.image)}</div></td>
        <td>${chip(c.state === "running" ? "ok" : "crit", c.state)} ${c.health ? chip(c.health === "healthy" ? "ok" : "warn", c.health) : ""}</td>
        <td class="n">${l.cpu != null ? l.cpu.toFixed(1) + "%" : "–"}</td><td class="n">${bytes(l.mem)}</td><td class="n">${c.restart_count}</td>
        <td class="muted">${esc(c.compose_project || "–")}</td>
        <td>${c.mounts.length ? `<details><summary>${c.mounts.length} mount${c.mounts.length > 1 ? "s" : ""}</summary><div class="mono">${c.mounts.map((mm) => esc((mm.source || mm.name) + " → " + mm.dest + (mm.rw ? "" : " (ro)"))).join("<br>")}</div></details>` : '<span class="muted">none</span>'}</td>
        <td class="mono">${esc(c.ports.join(" "))}</td><td style="white-space:nowrap">${verbs.map((v) => actBtn(v, { type: "container", verb: v, target: c.name })).join(" ")}</td></tr>`;
    }).join("");
    const table = panel(`Containers (updated ${ago(d.inventory.ts)})`, `<div class="scroll"><table class="t"><tr><th>Container</th><th>State</th><th class="n">CPU</th><th class="n">RAM</th><th class="n">Restarts</th><th>Compose</th><th>Mounts</th><th>Ports</th><th></th></tr>${rows}</table></div>`, { span: 24, h: 6 }) +
      panel("Images", `<div class="scroll"><table class="t"><tr><th>Image</th><th class="n">Size</th><th>Used</th></tr>${(inv.images || []).sort((a, b) => b.size - a.size).map((i) => `<tr><td class="mono">${esc(i.tags[0] || i.id)}</td><td class="n">${bytes(i.size)}</td><td>${i.in_use ? chip("ok", "in use") : chip("muted", "unused")}</td></tr>`).join("")}</table></div>`, { span: 12, h: 5, info: "Guardian never prunes. Review before removing." }) +
      panel("Volumes", `<div class="scroll"><table class="t"><tr><th>Volume</th><th>Used</th></tr>${(inv.volumes || []).map((v) => `<tr><td class="mono">${esc(v.name)}</td><td>${v.in_use ? chip("ok", "in use") : chip("muted", "unused")}</td></tr>`).join("") || '<tr><td class="muted">No named volumes</td></tr>'}</table></div>`, { span: 12, h: 5 });
    return R("dk-top", "Overview", top + mid) + R("dk-charts", "Containers over time", graphs) + R("dk-inv", "Inventory & control", table);
  },
};
const ncpuOf = (L) => L.ncpu || 1;

D.immich = {
  title: "Immich", live: true,
  async render() {
    const [d, m] = await Promise.all([api("/api/immich"), metrics()]);
    const i = d.immich.data || {}, b = d.backup.data || {}, lastB = b.last || {};
    const dir = (n) => d.dirs.find((x) => x.path.endsWith("/" + n)) || {};
    const up = dir("upload"), vid = dir("encoded-video"), th = dir("thumbs"), removed = dir("removed");
    const bAge = lastB.finished ? (Date.now() - Date.parse(lastB.finished)) / 86400000 : null;
    const names = (i.container_details || []).map((c) => c.name);
    const cs = (col) => { const p = pivot(m.containers, "name", col, names); return { t: p.t, series: [...p.by.entries()].map(([n, v], k) => ({ name: n.replace("immich_", ""), color: pal(k), values: v })) }; };
    const nextRun = b.timer?.NextElapseUSecRealtime || "";
    const top = stat({ title: "Immich", value: i.reachable ? "Online" : "Offline", color: i.reachable ? "var(--green)" : "var(--red)", span: 4, dot: true, sub: `version ${esc(i.version || "?")}` }) +
      stat({ title: "Activity", value: i.busy ? "Processing" : "Idle", color: i.busy ? "var(--orange)" : "var(--green)", span: 4, small: true, sub: i.jobs_active != null ? `${i.jobs_active} active jobs` : "add an API key for job details" }) +
      stat({ title: "Originals", value: bytes(up.bytes), color: "var(--cyan)", span: 4, sub: up.files ? `${num(up.files)} files` : "measured daily" }) +
      stat({ title: "Transcoded video", value: bytes(vid.bytes), color: "var(--cyan)", span: 4, small: true, sub: vid.files ? `${num(vid.files)} files` : "" }) +
      stat({ title: "Thumbnails", value: bytes(th.bytes), color: "var(--cyan)", span: 4, small: true, sub: th.files ? `${num(th.files)} files` : "" }) +
      stat({ title: "Containers", value: `${(i.containers || []).length}/${names.length || 4}`, color: (i.missing_containers || []).length ? "var(--red)" : "var(--green)", span: 4, sub: (i.missing_containers || []).length ? "missing: " + esc(i.missing_containers.join(", ")) : "all running" });
    const backup = !b.enabled ? "" : stat({ title: "Last backup", value: b.running ? "Running" : lastB.finished ? ago(lastB.finished) : "Never", color: b.running ? "var(--cyan)" : lastB.result === "failed" || bAge == null || bAge > 8 ? "var(--red)" : "var(--green)", span: 4, h: 3, dot: true, sub: esc(lastB.message || "") }) +
      stat({ title: "Next backup", value: nextRun ? nextRun.split(" ").slice(0, 1).concat(nextRun.split(" ")[2]?.slice(0, 5) || []).join(" ") : "not scheduled", color: "var(--strong)", small: true, span: 4, h: 3,
        sub: esc(nextRun.split(" ")[1] || "") + `<div style="margin-top:8px">${(b.unit ? actBtn("Run backup now", { type: "backup_run" }, "primary sm") : "")}</div>` }) +
      gauge({ title: "Backup drive", value: b.drive?.total ? (b.drive.used / b.drive.total) * 100 : null, sub: b.drive?.connected ? `${bytes(b.drive.free)} free` : "not connected", span: 4, h: 3 }) +
      stat({ title: "Backup folder: removed/", value: bytes(removed.bytes || 0), color: "var(--cyan)", small: true, span: 4, h: 3, info: "Size of a removed/ folder in the backup target, if your backup job keeps deleted files there", sub: removed.files ? `${num(removed.files)} files` : "" }) +
      panel("Backup target", `<div class="kv"><div>Folder</div><div class="mono">${esc(lastB.target || "–")}</div><div>Drive</div><div class="mono">${esc(b.drive?.mount || "–")} ${esc(b.drive?.fstype || "")}</div><div>Result</div><div>${lastB.result ? chip(lastB.result === "ok" ? "ok" : lastB.result === "failed" ? "crit" : "warn", lastB.result) : "–"}</div></div>`, { span: 8, h: 3 });
    const cpu = cs("cpu"), mem = cs("mem");
    const graphs = timeseries({ title: "Immich CPU usage", key: "im-cpu", t: cpu.t, series: cpu.series, fmt: (v) => pct(v), span: 12, info: "% of one core" }) +
      timeseries({ title: "Immich memory", key: "im-mem", t: mem.t, series: mem.series, fmt: bytes, span: 12 });
    const detail = panel("Containers", `<table class="t"><tr><th>Container</th><th>State</th><th class="n">CPU</th><th class="n">RAM</th><th class="n">Restarts</th></tr>
      ${(i.container_details || []).map((c) => { const l = (i.containers || []).find((x) => x.name === c.name) || {};
        return `<tr><td>${esc(c.name)}</td><td>${chip(c.state === "running" ? "ok" : "crit", c.state)} ${c.health ? chip(c.health === "healthy" ? "ok" : "warn", c.health) : ""}</td><td class="n">${l.cpu?.toFixed(1) ?? "–"}%</td><td class="n">${bytes(l.mem)}</td><td class="n">${c.restart_count}</td></tr>`; }).join("")}</table>`, { span: 12, h: 4 }) +
      panel("Library folders", barGauge(d.dirs.filter((x) => !x.path.endsWith("/removed")).sort((a, x) => x.bytes - a.bytes).map((x) => ({ name: x.path.split("/").pop(), value: x.bytes })), { fmt: bytes }) || '<div class="empty">Measured once a day while the system is idle</div>', { span: 12, h: 4 }) +
      panel("Immich's own daily database dumps", `<div class="scroll"><table class="t"><tr><th>File</th><th class="n">Size</th><th>When</th></tr>${(i.db_dumps || []).slice().reverse().map((x) => `<tr><td class="mono">${esc(x.name)}</td><td class="n">${bytes(x.size)}</td><td class="muted">${ago(x.mtime)}</td></tr>`).join("")}</table></div>`, { span: 12, h: 4 }) +
      panel("Protected paths", `<div class="kv"><div>Compose file</div><div class="mono">${esc(i.compose_file)}</div><div>Photos &amp; videos</div><div class="mono">${esc(i.paths?.upload)}</div><div>Database</div><div class="mono">${esc(i.paths?.database)}</div></div>
        <p class="muted small">Never scanned, quarantined or changed by Guardian:</p>${d.protected_paths.map((p) => `<div class="mono">${esc(p)}</div>`).join("")}`, { span: 12, h: 4 });
    return R("im-status", "Immich", top) + (backup ? R("im-backup", "Backup job", backup) : "") + R("im-charts", "Resource usage", graphs) + R("im-detail", "Details", detail);
  },
};

D.storage = {
  title: "Storage", live: true,
  async render() {
    const [d, m] = await Promise.all([api("/api/storage"), metrics()]);
    const s = d.storage.data || {}, fs = s.filesystems || [], sm = (d.smart.data || {}).drives || [];
    const nG = fs.length + fs.filter((f) => f.inodes_pct != null).length, gw = Math.max(4, Math.floor(24 / Math.max(1, nG)));
    const gauges = fs.map((f) => gauge({ title: `Used (${f.mount})`, value: f.percent, sub: `${bytes(f.free)} free of ${bytes(f.total)}`, span: gw, h: 3 }) +
      (f.inodes_pct != null ? gauge({ title: `Inodes (${f.mount})`, value: f.inodes_pct, fmt: (v) => pct(v, 2), span: gw, h: 3 }) : "")).join("");
    const sw = Math.max(4, Math.floor(24 / Math.max(1, fs.length)));
    const growth = fs.map((f) => stat({ title: `Growth per day (${f.mount})`, value: f.growth_per_day != null ? bytes(f.growth_per_day) : "collecting", color: f.growth_per_day != null ? "var(--cyan)" : "var(--muted)", span: sw, h: 1, small: true,
      sub: f.growth_per_day > 0 ? `full in ~${Math.round(f.free / f.growth_per_day)} days` : "needs 6 h of history" })).join("");
    const hist = pivot(d.history.map((h) => ({ ...h, pct: (h.used / h.total) * 100 })), "mount", "pct");
    const usage = timeseries({ title: "Filesystem usage (30 days)", key: "st-usage", gap: 4 * 3600, t: hist.t, fmt: (v) => pct(v), max: 100, span: 12, series: [...hist.by.entries()].map(([n, v], i) => ({ name: n, color: pal(i), values: v })) }) +
      timeseries({ title: "Disk I/O", key: "st-io", t: colOf(m.samples, "ts"), fmt: bps, span: 12, series: [{ name: "read", color: pal(2), values: colOf(m.samples, "disk_read_bps") }, { name: "write", color: pal(3), values: colOf(m.samples, "disk_write_bps") }] });
    const smart = sm.map((x) => {
      const bad = x.SmartFailing || (x.SmartCriticalWarning || []).length;
      const hours = x.SmartPowerOnHours || (x.SmartPowerOnSeconds ? Math.round(x.SmartPowerOnSeconds / 3600) : null);
      return stat({ title: x.Model || x.path, value: x.temp_c ? x.temp_c.toFixed(0) : x.has_data ? "OK" : "n/a", unit: x.temp_c ? "°C" : "", raw: x.temp_c, th: TH.temp, color: bad ? "var(--red)" : x.temp_c ? undefined : "var(--muted)", span: 8, h: 2,
        sub: `${bad ? "SMART FAILING" : x.has_data ? "healthy" : "no SMART over this bridge"} · ${esc(x.ConnectionBus || "internal")}${hours ? ` · ${num(hours)} h on` : ""}${x.SmartNumBadSectors > 0 ? ` · ${x.SmartNumBadSectors} bad sectors` : ""}` });
    }).join("");
    const blk = panel("Disks & partitions", `<div class="scroll"><table class="t"><tr><th>Device</th><th>Model</th><th>Bus</th><th class="n">Size</th><th>Partitions</th></tr>${(s.block || []).map((bd) => `<tr><td class="mono">${esc(bd.path)}</td><td>${esc(bd.model || "")}</td><td>${esc(bd.tran || "")}</td><td class="n">${bytes(bd.size)}</td><td class="muted">${(bd.children || []).map((c) => esc(`${c.name} ${c.fstype || ""} ${(c.mountpoints || []).filter(Boolean).join(",")}`)).join("<br>") || "no partitions / not mounted"}</td></tr>`).join("")}</table></div>`, { span: 12, h: 4 }) +
      panel("Largest measured folders", barGauge(d.dirs.map((x) => ({ name: x.path.replace(/^.*\/(immich-backups|library)\//, "$1/"), value: x.bytes })).sort((a, x) => x.value - a.value), { fmt: bytes }) || '<div class="empty">Measured once a day</div>', { span: 12, h: 4 });
    const log = !d.backup?.data?.enabled ? "" : panel("Backup log", `<pre class="log" style="height:100%">${esc(d.backup_log || "No backup has run yet.")}</pre>`, { span: 24, h: 5 });
    return R("st-fs", "Filesystems", gauges + growth) + R("st-hist", "History", usage) + R("st-smart", "Drive health (SMART)", smart) + R("st-inv", "Inventory", blk) + (log ? R("st-log", "Backup log", log) : "");
  },
};

D.services = {
  title: "Services", live: false,
  vars: () => ({ state: { label: "state", options: ["running", "enabled", "failed", "all"] }, q: { label: "filter", text: true } }),
  async render(arg) {
    if (arg) return serviceDetail(decodeURIComponent(arg));
    const s = await api("/api/services"), d = s.data || {};
    let list = d.services || [];
    const st = state.vars.state || "running", q = (state.vars.q || "").toLowerCase();
    if (st === "running") list = list.filter((x) => x.sub === "running");
    if (st === "failed") list = list.filter((x) => x.active === "failed");
    if (st === "enabled") list = list.filter((x) => x.enabled === "enabled");
    if (q) list = list.filter((x) => (x.unit + x.description).toLowerCase().includes(q));
    list.sort((a, b) => b.mem - a.mem);
    const all = d.services || [];
    const top = stat({ title: "Running", value: d.running, color: "var(--green)", span: 4, h: 1 }) +
      stat({ title: "Failed", value: (d.failed || []).length, raw: (d.failed || []).length, th: [[0, "green"], [1, "red"]], span: 4, h: 1 }) +
      stat({ title: "Enabled at boot", value: all.filter((x) => x.enabled === "enabled").length, color: "var(--cyan)", span: 4, h: 1 }) +
      stat({ title: "Optional & running", value: all.filter((x) => x.risk === "low" && x.sub === "running").length, color: "var(--orange)", span: 4, h: 1, info: "Known-optional services that are running; see Recommendations" }) +
      stat({ title: "Known to Guardian", value: `${all.filter((x) => x.known).length}/${all.length}`, color: "var(--strong)", span: 4, h: 1, small: true }) +
      stat({ title: "Updated", value: ago(s.ts), color: "var(--muted)", span: 4, h: 1, small: true });
    const mem = panel("Memory by service", barGauge(all.filter((x) => x.mem).sort((a, b) => b.mem - a.mem).slice(0, 14).map((x) => ({ name: x.unit.replace(/\.service$/, ""), value: x.mem })), { fmt: bytes }), { span: 8, h: 6 });
    const riskChip = (x) => chip(x.protected ? "crit" : x.risk === "low" ? "ok" : x.risk === "unknown" ? "muted" : "warn", x.protected ? "protected" : x.risk);
    const table = panel(`Services (${list.length})`, `<div class="scroll"><table class="t"><tr><th>Unit</th><th>Description</th><th>State</th><th>Boot</th><th class="n">Memory</th><th class="n">CPU</th><th>Category</th><th>If stopped</th></tr>
      ${list.map((x) => `<tr><td><a href="#/services/${encodeURIComponent(x.unit)}">${esc(x.unit)}</a></td><td class="muted">${esc(x.description)}</td>
      <td>${chip(x.active === "failed" ? "crit" : x.sub === "running" ? "ok" : "muted", x.sub)}</td><td class="muted">${esc(x.enabled)}</td>
      <td class="n">${x.mem ? bytes(x.mem) : "–"}</td><td class="n">${x.cpu == null ? "–" : x.cpu.toFixed(2) + "%"}</td><td class="muted">${esc(x.category)}</td><td>${riskChip(x)}</td></tr>`).join("")}</table></div>`, { span: 16, h: 6 });
    const user = panel("Your user services & timers", `<div class="scroll">${(d.user_units || []).filter((u) => u.active === "active").map((u) => `<div class="mono">${esc(u.unit)}</div>`).join("")}</div>`, { span: 24, h: 3 });
    return R("sv-sum", "Summary", top) + R("sv-list", "Services", table + mem) + R("sv-user", "User units", user);
  },
};
async function serviceDetail(unit) {
  const d = await api("/api/services/" + encodeURIComponent(unit));
  const p = d.props, kb = d.kb;
  const acts = d.allowed_actions.map((v) => actBtn(v[0].toUpperCase() + v.slice(1), { type: "service", verb: v, target: unit }, v === "stop" || v === "disable" ? "danger" : "")).join(" ");
  const hist = d.history.map((h) => `<tr><td>#${h.id}</td><td>${new Date(h.ts * 1000).toLocaleString()}</td><td>${esc(h.action)}</td><td>${chip(h.status === "done" ? "ok" : "warn", h.status)}</td>
    <td>${h.action.startsWith("service.") && h.status === "done" ? actBtn("Roll back", { type: "service_rollback", audit_id: h.id }) : ""}</td></tr>`).join("");
  const memV = p.MemoryCurrent && p.MemoryCurrent !== "[not set]" ? +p.MemoryCurrent : null;
  const head = stat({ title: "State", value: p.ActiveState, color: p.ActiveState === "active" ? "var(--green)" : p.ActiveState === "failed" ? "var(--red)" : "var(--muted)", span: 4, h: 1, small: true, sub: esc(p.SubState) }) +
    stat({ title: "Boot", value: p.UnitFileState, color: "var(--cyan)", span: 4, h: 1, small: true, sub: `preset ${esc(p.UnitFilePreset)}` }) +
    stat({ title: "Memory", value: memV ? bytes(memV) : "–", color: "var(--green)", span: 4, h: 1, small: true }) +
    stat({ title: "CPU time", value: p.CPUUsageNSec && p.CPUUsageNSec !== "[not set]" ? (p.CPUUsageNSec / 1e9).toFixed(1) + " s" : "–", color: "var(--green)", span: 4, h: 1, small: true }) +
    stat({ title: "Risk if stopped", value: d.protected ? "protected" : kb.risk, color: d.protected ? "var(--red)" : kb.risk === "low" ? "var(--green)" : "var(--orange)", span: 4, h: 1, small: true, sub: `confidence ${esc(d.confidence)}` }) +
    stat({ title: "Restarts", value: p.NRestarts, raw: +p.NRestarts, th: [[0, "green"], [3, "orange"], [10, "red"]], span: 4, h: 1, small: true });
  const body = panel("What it is", `<p style="margin-top:0">${esc(kb.purpose)}</p><div class="kv"><div>Description</div><div>${esc(p.Description)}</div><div>Category</div><div>${esc(kb.category)}</div>
      <div>Package</div><div>${esc(d.package || "–")}</div><div>Unit file</div><div class="mono">${esc(p.FragmentPath)}</div><div>Running since</div><div>${esc(p.ActiveEnterTimestamp || "–")}</div></div>
      <p>${d.immich_related ? chip("warn", "supports Docker/Immich") : ""} ${d.backup_related ? chip("warn", "needed for backups") : ""}</p>`, { span: 12, h: 5 }) +
    panel("Why it runs & what stopping it does", `<ul style="margin-top:0">${d.why_running.map((x) => `<li>${esc(x)}</li>`).join("") || "<li>Unknown</li>"}</ul>
      <p><b>Stop:</b> ${esc(d.consequences.stop)}</p><p><b>Disable:</b> ${esc(d.consequences.disable)}</p>`, { span: 12, h: 5 }) +
    panel("Dependencies", `<p class="muted">Requires: ${esc(d.requires.join(", ") || "none")}</p><p class="muted">Wants: ${esc(d.wants.join(", ") || "none")}</p>
      <details><summary>${d.reverse_dependencies.length} units depend on it</summary><p class="mono">${esc(d.reverse_dependencies.join("\n"))}</p></details>`, { span: 12, h: 4 }) +
    panel("Processes & investigation", `${d.processes.map((x) => `<div class="mono">${x.pid}: ${esc(x.cmd)}</div>`).join("") || '<div class="muted">none</div>'}
      <p class="muted" style="margin-bottom:4px">Investigate:</p>${d.investigate.map((c) => `<div class="mono">${esc(c)}</div>`).join("")}`, { span: 12, h: 4 }) +
    panel("Actions", `${d.protected ? "<p>Guardian will not change this service: it is essential to the system, desktop, Docker or backups.</p>" : acts || '<p class="muted">No actions apply in the current state.</p>'}
      ${!d.executor && !d.protected ? `<p class="muted">Service actions need the root helper: <span class="mono">${esc(d.executor_install)}</span></p>` : ""}
      ${hist ? `<table class="t" style="margin-top:8px">${hist}</table>` : ""}`, { span: 24, h: 3 });
  return `<p style="margin:6px 0"><a href="#/services">← Services</a></p>` + R("svd-h", unit, head) + R("svd-b", "Details", body);
}

D.network = {
  title: "Network", live: true,
  async render() {
    const [n, m, o] = await Promise.all([api("/api/network"), metrics(), api("/api/overview")]);
    const d = n.data || {}, S = m.samples, t = colOf(S, "ts"), L = o.live.data || {};
    const rxMax = niceMax(Math.max(65536, ...colOf(S, "net_rx_bps").filter(Boolean)) * 1.1), txMax = niceMax(Math.max(65536, ...colOf(S, "net_tx_bps").filter(Boolean)) * 1.1);
    const wifi = Object.entries(d.wifi_signal_dbm || {});
    const top = stat({ title: "Internet", value: d.internet ? "Online" : "Offline", color: d.internet ? "var(--green)" : "var(--red)", span: 4, dot: true }) +
      stat({ title: "DNS", value: d.dns ? "OK" : "Failing", color: d.dns ? "var(--green)" : "var(--red)", span: 4 }) +
      stat({ title: "Firewall (ufw)", value: d.firewall?.ufw_enabled ? "On" : "Off", color: d.firewall?.ufw_enabled ? "var(--green)" : "var(--orange)", span: 4 }) +
      stat({ title: "Wi-Fi signal", value: wifi.length ? wifi[0][1] : "–", unit: wifi.length ? "dBm" : "", raw: wifi.length ? -wifi[0][1] : null, th: [[0, "green"], [67, "orange"], [80, "red"]], span: 4, sub: wifi.length ? esc(wifi[0][0]) : "wired or no Wi-Fi" }) +
      gauge({ title: "Download", value: L.net?.rx_bps, max: rxMax, fmt: bps, th: [[0, "green"], [rxMax * 0.7, "orange"], [rxMax * 0.9, "red"]], span: 4, h: 2 }) +
      gauge({ title: "Upload", value: L.net?.tx_bps, max: txMax, fmt: bps, th: [[0, "green"], [txMax * 0.7, "orange"], [txMax * 0.9, "red"]], span: 4, h: 2 });
    const lat = pivot(m.checks, "name", "ms").by;
    const checks = (o.checks || []).map((c) => stat({ title: c.name, value: checkValue(c), color: c.ok ? "var(--green)" : "var(--red)", span: 8, h: 1, sub: `${c.ms} ms · ${esc(c.url)}`, spark: lat.get(c.name) || [] })).join("");
    const graphs = timeseries({ title: "Traffic", key: "nw-traffic", t, fmt: bps, span: 12, series: [{ name: "download", color: pal(0), values: colOf(S, "net_rx_bps") }, { name: "upload", color: pal(1), values: colOf(S, "net_tx_bps") }] }) +
      timeseries({ title: "Sockets", key: "nw-sockets", t, fmt: fix(0), span: 12, series: [{ name: "tcp established", color: pal(0), values: colOf(S, "tcp_estab") }, { name: "tcp listen", color: pal(2), values: colOf(S, "tcp_listen") }, { name: "tcp time_wait", color: pal(3), values: colOf(S, "tcp_tw") }, { name: "udp", color: pal(6), values: colOf(S, "udp") }] });
    const tables = panel("Interfaces", `<table class="t"><tr><th>Name</th><th>State</th><th class="n">Speed</th><th>Addresses</th></tr>${(d.interfaces || []).map((i) => `<tr><td>${esc(i.name)}</td><td>${chip(i.up ? "ok" : "muted", i.up ? "up" : "down")}</td><td class="n">${i.speed ? i.speed + " Mb/s" : "–"}</td><td class="mono">${esc(i.addrs.join(" "))}</td></tr>`).join("")}</table>`, { span: 12, h: 5 }) +
      panel("Listening ports", `<div class="scroll"><table class="t"><tr><th class="n">Port</th><th>Address</th><th>Owner</th><th>Reachable from</th></tr>${(d.listening || []).map((l) => `<tr><td class="n">${l.port}</td><td class="mono">${esc(l.ip)}</td><td>${esc(l.process || "(root process)")}</td><td>${l.exposed ? chip("warn", "network") : chip("ok", "this machine")}</td></tr>`).join("")}</table></div>`, { span: 12, h: 5 });
    return R("nw-top", "Status", top) + R("nw-checks", "Endpoint checks", checks) + R("nw-charts", "Traffic", graphs) + R("nw-tables", "Interfaces & ports", tables);
  },
};

D.duplicates = {
  title: "Duplicate files", live: false,
  async render(arg) {
    if (arg) return dupScan(+arg);
    const [d, qf] = await Promise.all([api("/api/duplicates"), api("/api/duplicates/quarantine")]);
    state.dupRunning = d.running;
    const last = d.scans.find((x) => x.status === "done");
    const top = stat({ title: "Last scan", value: last ? ago(last.finished) : "never", color: last ? "var(--strong)" : "var(--muted)", small: true, span: 6, sub: last ? `#${last.id} · ${num(last.files_seen)} files checked` : "start one below" }) +
      stat({ title: "Duplicate groups", value: last ? num(last.groups) : "–", color: "var(--cyan)", span: 6, sub: "in the last scan" }) +
      stat({ title: "Reclaimable", value: bytes(last?.reclaimable_now || 0), color: (last?.reclaimable_now || 0) > 0 ? "var(--orange)" : "var(--green)", span: 6, sub: last && last.reclaimable_now !== last.reclaimable ? `${bytes(last.reclaimable)} when scanned` : "if you keep one copy of each" }) +
      stat({ title: "In quarantine", value: bytes(d.quarantine.bytes), color: d.quarantine.files ? "var(--yellow)" : "var(--green)", span: 6, sub: `${num(d.quarantine.files)} files · restorable` });
    let progress = "";
    if (d.running) {
      const p = d.progress || {}, frac = p.bytes_total ? Math.min(1, (p.bytes_hashed || 0) / p.bytes_total) : null;
      progress = panel(`Scan #${p.scan ?? ""} in progress`, `<div class="dup-prog">
          <div class="row-kv"><span>Phase</span><b>${esc(p.phase || "starting")}</b><span>Files listed</span><b>${num(p.files || 0)}</b>
          <span>Hashed</span><b>${bytes(p.bytes_hashed || 0)}${p.bytes_total ? " of " + bytes(p.bytes_total) : ""}</b><span>Running for</span><b>${p.started ? Math.round((Date.now() / 1000 - p.started) / 60) + " min" : "–"}</b></div>
          <div class="pbar"><i style="width:${frac == null ? 8 : Math.max(2, frac * 100)}%" class="${frac == null ? "indet" : ""}"></i></div>
          <div class="muted small">Reading is limited to ${d.rate} MB/s and pauses automatically while the system is busy. You can leave this page.</div>
          <button class="btn sm" id="dup-cancel">Cancel scan</button></div>`, { span: 24, h: "auto" });
    }
    const roots = state.dupRoots ?? d.default_roots.join("\n");
    const form = panel("New scan", `<label class="muted" for="dup-roots">Folders to scan, one per line</label>
      <textarea class="in" id="dup-roots" rows="5" spellcheck="false">${esc(roots)}</textarea>
      <div class="dup-actions"><button class="btn primary" id="dup-start" ${d.running ? "disabled" : ""}>${d.running ? "A scan is running…" : "Start scan"}</button>
      <span class="muted small">Read-only. Files smaller than ${bytes(d.min_size)} are ignored.</span></div>`, { span: 12, h: "auto" });
    const how = panel("How it works", `<ol class="steps">
      <li><b>Scan</b> reads the folders you choose. Immich, database, Docker and backup folders are always skipped:<div class="mono muted small">${d.protected.map(esc).join(" · ")}</div></li>
      <li><b>Match</b> files by size, then a fingerprint of the first and last 64 KB, then a full SHA-256. Only byte-identical files count; similar-looking photos never do.</li>
      <li><b>Review</b> each group and tick the copies to remove. At least one copy always stays.</li>
      <li><b>Quarantine</b> moves them to <span class="mono">.guardian-quarantine</span> on the same disk. Nothing is deleted yet and you can restore at any time.</li>
      <li><b>Delete permanently</b> from quarantine when you are sure (you type DELETE to confirm).</li></ol>`, { span: 12, h: "auto" });
    const scans = panel("Scans", d.scans.length ? `<table class="t"><tr><th>#</th><th>Started</th><th>Folders</th><th>Status</th><th class="n">Files</th><th class="n">Groups</th><th class="n">Reclaimable</th><th></th></tr>
      ${d.scans.map((x) => `<tr><td><a href="#/duplicates/${x.id}">#${x.id}</a></td><td class="muted">${new Date(x.started * 1000).toLocaleString()}</td><td class="mono">${JSON.parse(x.roots).map(esc).join("<br>")}</td>
        <td>${chip(x.status === "done" ? "ok" : x.status === "running" ? "blue" : "warn", x.status)}</td><td class="n">${num(x.files_seen || 0)}</td><td class="n">${x.groups || 0}</td><td class="n">${bytes(x.reclaimable_now)}</td>
        <td style="white-space:nowrap">${x.status === "done" ? `<a class="btn sm" href="#/duplicates/${x.id}" style="display:inline-flex;align-items:center">Review</a> ` : ""}${x.status !== "running" ? `<button class="btn sm" data-forget="${x.id}" title="Remove these results (files on disk are not touched)">Forget</button>` : ""}</td></tr>`).join("")}</table>`
      : '<div class="empty">No scans yet. Start one above.</div>', { span: 24, h: "auto" });
    const quar = panel(`Quarantine (${num(qf.length)} files, ${bytes(sum(qf.map((f) => f.size)))})`, qf.length ? `<table class="t"><tr><th>Original location</th><th class="n">Size</th><th>Scan</th><th></th></tr>
      ${qf.map((f) => `<tr><td class="mono">${esc(f.path)}</td><td class="n">${bytes(f.size)}</td><td><a href="#/duplicates/${f.scan_id}">#${f.scan_id}</a></td>
        <td style="white-space:nowrap">${actBtn("Restore", { type: "restore", scan_id: f.scan_id, paths: [f.path] })} ${actBtn("Delete permanently", { type: "purge", scan_id: f.scan_id, paths: [f.path] }, "sm danger")}</td></tr>`).join("")}</table>`
      : '<div class="empty">Quarantine is empty.</div>', { span: 24, h: "auto" });
    return R("dp-top", "Summary", top + progress) + R("dp-new", "Find duplicates", form + how) + R("dp-scans", "Scans", scans) + R("dp-q", "Quarantine", quar);
  },
};
async function dupScan(sid) {
  const q = state.dupFilter || "";
  const d = await api(`/api/duplicates/${sid}?q=${encodeURIComponent(q)}`);
  const s = d.scan;
  const top = stat({ title: "Duplicate groups", value: num(d.total_groups), color: "var(--cyan)", span: 6, h: 1 }) +
    stat({ title: "Reclaimable now", value: bytes(d.reclaimable_now), color: d.reclaimable_now ? "var(--orange)" : "var(--green)", span: 6, h: 1 }) +
    stat({ title: "Files checked", value: num(s.files_seen), color: "var(--strong)", span: 6, h: 1, small: true, sub: esc(s.message || "") }) +
    stat({ title: "In quarantine", value: num(d.quarantined), color: d.quarantined ? "var(--yellow)" : "var(--green)", span: 6, h: 1, small: true, sub: esc(JSON.parse(s.roots).join(", ")) });
  const groups = d.groups.map((g) => `<div class="dgrp" data-grp="${g.grp}">
      <div class="dgh"><b>${g.files.length} copies</b><span>${bytes(g.size)} each</span><span class="${g.reclaimable ? "warn-t" : "muted"}">${g.reclaimable ? bytes(g.reclaimable) + " reclaimable" : "nothing to reclaim"}</span><span class="mono muted small">sha256 ${esc(g.hash.slice(0, 12))}…</span></div>
      ${g.files.map((f) => {
        const i = f.path.lastIndexOf("/"), dir = f.path.slice(0, i + 1), name = f.path.slice(i + 1);
        return `<label class="dfile ${f.state}"><input type="checkbox" class="dup" value="${esc(f.path)}" data-state="${esc(f.state)}" data-size="${g.size}" data-mtime="${f.mtime}" ${f.state === "present" || f.state === "quarantined" ? "" : "disabled"}>
          <span class="dpath mono"><span class="muted">${esc(dir)}</span>${esc(name)}</span>
          <span class="muted small">${new Date(f.mtime * 1000).toLocaleString()}</span>
          <span>${chip(f.state === "present" ? "ok" : f.state === "quarantined" ? "warn" : "muted", f.state)}</span></label>`;
      }).join("")}</div>`).join("");
  const tools = `<div class="dup-tools">
      <input class="in" id="dup-filter" placeholder="Filter by path…" value="${esc(q)}" style="max-width:260px">
      <button class="btn sm" data-select="first">Keep first copy</button>
      <button class="btn sm" data-select="newest">Keep newest copy</button>
      <button class="btn sm" data-select="none">Clear</button>
      <span class="grow"></span><span id="dup-sel" class="muted">Nothing selected</span>
      <button class="btn sm primary" data-dup-action="quarantine" data-scan="${sid}">Move to quarantine</button>
      <button class="btn sm" data-dup-action="restore" data-scan="${sid}">Restore</button>
      <button class="btn sm danger" data-dup-action="purge" data-scan="${sid}">Delete permanently</button></div>`;
  const list = panel(`Groups${d.total_groups > d.groups.length ? ` (showing the ${d.groups.length} largest of ${d.total_groups})` : ""}`,
    tools + (groups || `<div class="empty">${q ? "No groups match this filter." : "No duplicates found in this scan."}</div>`), { span: 24, h: "auto" });
  return `<p style="margin:6px 0"><a href="#/duplicates">← Duplicate files</a></p>` + R("dps-top", `Scan #${sid} · ${new Date(s.started * 1000).toLocaleString()}`, top) + R("dps-g", "Review", list);
}
function updateDupSelection() {
  const sel = [...document.querySelectorAll("input.dup:checked")];
  const el = $("#dup-sel"); if (!el) return;
  el.textContent = sel.length ? `${sel.length} file${sel.length > 1 ? "s" : ""} selected · ${bytes(sum(sel.map((c) => +c.dataset.size)))}` : "Nothing selected";
}
document.addEventListener("change", (e) => { if (e.target.classList?.contains("dup")) updateDupSelection(); });
document.addEventListener("input", (e) => {
  if (e.target.id === "dup-roots") state.dupRoots = e.target.value;
  if (e.target.id === "dup-filter") { state.dupFilter = e.target.value; clearTimeout(window._df); window._df = setTimeout(() => render(false).then(() => { const f = $("#dup-filter"); if (f) { f.focus(); f.setSelectionRange(f.value.length, f.value.length); } }), 350); }
});
document.addEventListener("click", async (e) => {
  const t = e.target;
  if (t.id === "dup-start") {
    const roots = $("#dup-roots").value.split("\n").map((x) => x.trim()).filter(Boolean);
    t.disabled = true;
    try { const r = await post("/api/duplicates/scan", { roots }); toast("Scan #" + r.scan_id + " started"); state.dupRunning = true; render(true); }
    catch (err) { toast(err.message); t.disabled = false; }
  }
  if (t.id === "dup-cancel") { await post("/api/duplicates/cancel"); toast("Cancelling scan…"); setTimeout(() => render(true), 800); }
  if (t.dataset?.forget) {
    try { await post(`/api/duplicates/${t.dataset.forget}/forget`); toast("Scan results removed"); render(true); } catch (err) { toast(err.message); }
  }
  if (t.dataset?.select) {
    document.querySelectorAll(".dgrp").forEach((g) => {
      const boxes = [...g.querySelectorAll("input.dup[data-state=present]")];
      let keep = boxes[0];
      if (t.dataset.select === "newest") keep = boxes.reduce((a, b) => (+b.dataset.mtime > +a.dataset.mtime ? b : a), boxes[0]);
      boxes.forEach((b) => { b.checked = t.dataset.select !== "none" && b !== keep; });
      g.querySelectorAll("input.dup[data-state=quarantined]").forEach((b) => { if (t.dataset.select === "none") b.checked = false; });
    });
    updateDupSelection();
  }
  if (t.dataset?.dupAction) {
    const want = t.dataset.dupAction === "quarantine" ? "present" : "quarantined";
    const paths = [...document.querySelectorAll("input.dup:checked")].filter((c) => c.dataset.state === want).map((c) => c.value);
    if (!paths.length) { toast(want === "present" ? "Tick the copies you want to remove first." : "Tick files that are in quarantine first."); return; }
    act({ type: t.dataset.dupAction, scan_id: +t.dataset.scan, paths });
  }
});

// Suggested fixes that are shell commands get a copy button; advice is shown as text.
const shortImage = (i) => String(i).split("@")[0].split("/").pop();
const isCommand = (t) => /^(sudo |cd |chmod |chown |echo |docker |systemctl |apt |ufw )/.test(t);
D.security = {
  title: "Security & vulnerabilities", live: false,
  vars: () => ({ show: { label: "show", options: ["problems", "all", "passed"] } }),
  async render() {
    const d = await api("/api/security");
    const a = d.audit.data, iv = d.images?.data?.images ? d.images.data : null, scan = d.image_scan;
    state.secBusy = d.refreshing || scan.running;
    if (!a) return R("sec-wait", "Security review", panel("Running the first security review…", '<div class="empty">This takes a few seconds. The page refreshes by itself.</div>', { span: 24, h: 2 }));
    const F = a.findings, x = a.facts || {};
    const n = (st) => F.filter((f) => f.status === st).length;
    const fl = x.failed_logins || {};
    const exposed = (x.exposed || []).length, risky = (x.exposed || []).filter((r) => r.severity === "high").length;
    const secUpd = (x.updates || []).filter((u) => u.security).length;
    const gradeColor = a.score >= 75 ? "var(--green)" : a.score >= 40 ? "var(--orange)" : "var(--red)";
    const top = gauge({ title: "Security score", value: a.score, fmt: (v) => v.toFixed(0), th: [[0, "red"], [40, "orange"], [75, "green"]], span: 4, h: 3, sub: `grade ${a.grade}`, info: "100 minus penalties for failing and warning checks (capped per category)" }) +
      stat({ title: "Failing", value: n("fail"), color: n("fail") ? "var(--red)" : "var(--green)", span: 3, h: 3, sub: "checks" }) +
      stat({ title: "Warnings", value: n("warn"), color: n("warn") ? "var(--orange)" : "var(--green)", span: 3, h: 3, sub: "checks" }) +
      stat({ title: "Passing", value: n("pass"), color: "var(--green)", span: 3, h: 3, sub: `of ${F.length} checks` }) +
      stat({ title: "Security updates", value: secUpd, color: secUpd ? "var(--red)" : "var(--green)", span: 3, h: 3, sub: `${(x.updates || []).length} updates pending in total` }) +
      stat({ title: "Reboot needed", value: x.reboot_required ? "Yes" : "No", color: x.reboot_required ? "var(--orange)" : "var(--green)", span: 3, h: 3, small: true, sub: `kernel ${esc(x.kernel || "")}` }) +
      stat({ title: "Exposed ports", value: exposed, color: risky ? "var(--red)" : exposed ? "var(--orange)" : "var(--green)", span: 2, h: 3, sub: `${risky} high risk` }) +
      stat({ title: "Failed logins (24 h)", value: fl.total ?? "–", raw: fl.total, th: [[0, "green"], [11, "orange"], [51, "red"]], span: 3, h: 3,
        spark: (fl.series || []).map((p) => p[1]), sub: fl.readable === false ? "journal not readable" : `${fl.sudo || 0} sudo failures` });
    const tools = `<div class="dup-actions" style="margin:0 0 8px"><button class="btn sm primary" id="sec-refresh" ${d.refreshing ? "disabled" : ""}>${d.refreshing ? "Reviewing…" : "Run review now"}</button>
      <span class="muted small">Last review ${ago(a.ts)} · runs every 6 hours · read-only: fixes are suggestions you apply yourself</span></div>`;
    const show = state.vars.show || "problems";
    const list = F.filter((f) => show === "all" || (show === "passed" ? f.status === "pass" : f.status !== "pass"));
    const cats = [...new Set(list.map((f) => f.category))];
    const statusChip = (st) => chip(st === "fail" ? "crit" : st === "warn" ? "warn" : st === "pass" ? "ok" : "info", st === "fail" ? "fail" : st === "warn" ? "warning" : st === "pass" ? "pass" : "info");
    const findings = cats.map((c) => `<div class="sec-cat">${esc(c)}</div>` + list.filter((f) => f.category === c).map((f) => `
      <div class="ann ${f.status === "fail" ? "critical" : f.status === "warn" ? "warning" : f.status === "pass" ? "pass" : "info"}"><span class="bar"></span>
        <div class="body"><div class="ttl">${esc(f.title)}</div>${f.detail ? `<div class="d">${esc(f.detail)}</div>` : ""}
        ${f.fix ? (isCommand(f.fix) ? `<div class="fix"><code>${esc(f.fix)}</code><button class="btn sm" data-copy="${esc(f.fix)}">Copy</button></div>` : `<div class="d"><b>How to fix:</b> ${esc(f.fix)}</div>`) : ""}</div>
        <div class="tools">${statusChip(f.status)} ${chip("muted", f.severity)}</div></div>`).join("")).join("") || '<div class="empty">Nothing to show for this filter.</div>';
    const fpanel = panel(`Findings (${list.length})`, tools + findings, { span: 24, h: "auto" });

    // Container image vulnerabilities (Trivy)
    let imgs;
    if (scan.running) {
      const p = scan.progress || {};
      imgs = panel("Scanning container images", `<div class="dup-prog"><div class="row-kv"><span>Image</span><b class="mono">${esc(p.image || "starting")}</b><span>Progress</span><b>${(p.done ?? 0)} of ${p.total ?? "?"}</b></div>
        <div class="pbar"><i style="width:${p.total ? Math.max(3, (p.done / p.total) * 100) : 8}%" class="${p.total ? "" : "indet"}"></i></div>
        <div class="muted small">Trivy runs in a throwaway container limited to 1 CPU and 1 GB RAM, and pauses while the system is busy. The first run downloads its vulnerability database.</div>
        <button class="btn sm" id="sec-scan-cancel">Cancel</button></div>`, { span: 24, h: "auto" });
    } else if (!iv) {
      imgs = panel("Container image vulnerabilities", `<p style="margin-top:0">Checks every running container image (Immich included) against known CVEs using <a href="https://trivy.dev" target="_blank" rel="noopener">Trivy</a>, an open-source scanner.</p>
        <ul class="steps"><li>The first scan downloads the <span class="mono">${esc(scan.trivy_image)}</span> image (~250 MB) and its vulnerability database (~80 MB). They are cached for later scans.</li>
        <li>It runs with at most 1 CPU and 1 GB RAM and pauses while the system is busy. Expect a few minutes per image.</li>
        <li>After your first scan, Guardian repeats it weekly.</li></ul>
        <button class="btn primary" id="sec-scan">Scan images now</button>`, { span: 24, h: "auto" });
    } else {
      const ims = iv.images || [];
      const tot = (k) => sum(ims.map((i) => (i.counts || {})[k] || 0));
      const cards = ims.map((i) => stat({ title: shortImage(i.image), info: i.image, value: i.error ? "error" : (i.counts.CRITICAL + i.counts.HIGH), color: i.error ? "var(--muted)" : i.counts.CRITICAL ? "var(--red)" : i.counts.HIGH ? "var(--orange)" : "var(--green)", span: 6, h: 2, small: true,
        sub: i.error ? esc(i.error.slice(0, 80)) : `critical ${i.counts.CRITICAL} · high ${i.counts.HIGH} · medium ${i.counts.MEDIUM} · ${i.fixable} fixable` })).join("");
      const rank = { CRITICAL: 0, HIGH: 1 };
      const all = ims.flatMap((i) => (i.top || []).map((v) => ({ ...v, image: i.image }))).filter((v) => v.severity in rank)
        .sort((a, b) => rank[a.severity] - rank[b.severity] || (!a.fixed) - (!b.fixed));
      const sevChip = (sv) => chip(sv === "CRITICAL" ? "crit" : sv === "HIGH" ? "warn" : "info", sv.toLowerCase());
      const table = `<div class="scroll" style="max-height:420px"><table class="t"><tr><th>Severity</th><th>CVE</th><th>Image</th><th>Package</th><th>Installed</th><th>Fixed in</th><th>Title</th></tr>
        ${all.slice(0, 200).map((v) => `<tr><td>${sevChip(v.severity)}</td><td class="mono" style="white-space:nowrap"><a href="https://avd.aquasec.com/nvd/${esc(String(v.id).toLowerCase())}" target="_blank" rel="noopener">${esc(v.id)}</a></td><td class="mono muted">${esc(shortImage(v.image))}</td>
        <td class="mono">${esc(v.pkg)}</td><td class="mono muted">${esc(v.installed)}</td><td class="mono">${v.fixed ? esc(v.fixed) : '<span class="muted">no fix yet</span>'}</td><td class="muted">${esc(v.title)}</td></tr>`).join("") || '<tr><td colspan="7" class="empty">No critical or high vulnerabilities.</td></tr>'}</table></div>`;
      imgs = stat({ title: "Critical", value: tot("CRITICAL"), color: tot("CRITICAL") ? "var(--red)" : "var(--green)", span: 4, h: 2 }) +
        stat({ title: "High", value: tot("HIGH"), color: tot("HIGH") ? "var(--orange)" : "var(--green)", span: 4, h: 2 }) +
        stat({ title: "Medium", value: tot("MEDIUM"), color: "var(--yellow)", span: 4, h: 2 }) +
        stat({ title: "Low", value: tot("LOW"), color: "var(--cyan)", span: 4, h: 2 }) +
        stat({ title: "Fixable", value: sum(ims.map((i) => i.fixable || 0)), color: "var(--green)", span: 4, h: 2, sub: "a newer package exists" }) +
        stat({ title: "Last scan", value: ago(iv.finished), color: "var(--strong)", span: 4, h: 2, small: true, sub: `<button class="btn sm" id="sec-scan">Scan again</button>` }) +
        cards + panel("Critical and high vulnerabilities", `<p class="muted small" style="margin-top:0">Most of these are fixed by updating the image (for Immich: <span class="mono">docker compose pull &amp;&amp; docker compose up -d</span>, after making sure you have a backup). "No fix yet" means the upstream package has no patched version.</p>${table}`, { span: 24, h: "auto" });
    }

    const ports = panel("Reachable from the network", `<table class="t"><tr><th class="n">Port</th><th>Service</th><th>Risk</th><th>Why it matters</th></tr>
      ${(x.exposed || []).map((r) => `<tr><td class="n">${r.port}</td><td>${esc(r.service)}</td><td>${chip(r.severity === "high" ? "crit" : r.severity === "medium" ? "warn" : "info", r.severity)}</td><td class="muted">${esc(r.why || "")}</td></tr>`).join("") || '<tr><td colspan="4" class="empty">Nothing is reachable from the network.</td></tr>'}</table>`, { span: 12, h: "auto" });
    const ssh = x.ssh || {};
    const access = panel("Accounts & remote access", `<div class="kv">
      <div>Administrators (sudo)</div><div>${esc((x.sudo || []).join(", ") || "none")}</div>
      <div>Docker group (root-equivalent)</div><div>${esc((x.docker || []).join(", ") || "none")}</div>
      <div>Login accounts</div><div>${esc((x.login_users || []).join(", "))}</div>
      <div>SSH server</div><div>${ssh.running ? "running" : "not running"}</div>
      ${ssh.running ? `<div>SSH password login</div><div>${esc(ssh.passwordauthentication || "yes (default)")}</div><div>SSH root login</div><div>${esc(ssh.permitrootlogin || "prohibit-password (default)")}</div>` : ""}
      </div>${(fl.by_ip || []).length ? `<p class="muted small">Failed logins by source (24 h)</p>` + barGauge(fl.by_ip.map(([ip, c]) => ({ name: ip, value: c })), { fmt: num }) : ""}`, { span: 12, h: "auto" });
    const cpu = Object.entries(x.cpu_vulns || {});
    const hw = panel("CPU vulnerabilities", `<div class="scroll" style="max-height:360px"><table class="t"><tr><th>Issue</th><th>Status</th></tr>${cpu.map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td>${v.toLowerCase().startsWith("vulnerable") ? chip("crit", "vulnerable") : v.toLowerCase().startsWith("not affected") ? chip("ok", "not affected") : chip("blue", "mitigated")} <span class="muted small">${esc(v)}</span></td></tr>`).join("")}</table></div>`, { span: 12, h: "auto" }) +
      panel("Kernel hardening", `<table class="t"><tr><th>Setting</th><th>Value</th><th></th></tr>${(x.sysctl || []).map((k) => `<tr><td><div>${esc(k.desc)}</div><div class="mono muted small">${esc(k.key)}</div></td><td class="mono">${esc(k.value)}${k.ok ? "" : ` → ${esc(k.recommended)}`}</td><td>${k.ok ? chip("ok", "ok") : chip("warn", "not set")}</td></tr>`).join("")}
        <tr><td>AppArmor</td><td></td><td>${F.find((f) => f.id === "apparmor")?.status === "pass" ? chip("ok", "enabled") : chip("crit", "disabled")}</td></tr>
        <tr><td>Secure Boot</td><td></td><td>${x.secure_boot == null ? chip("muted", "unknown") : x.secure_boot ? chip("ok", "on") : chip("info", "off")}</td></tr></table>`, { span: 12, h: "auto" });
    const upd = (x.updates || []);
    const updates = panel(`Pending updates (${upd.length})`, `<table class="t"><tr><th>Package</th><th>Installed</th><th>Available</th><th>Source</th></tr>
      ${upd.map((u) => `<tr><td class="mono">${esc(u.package)}</td><td class="mono muted">${esc(u.installed)}</td><td class="mono">${esc(u.version)}</td><td>${u.security ? chip("crit", "security") : chip("muted", u.origin)}</td></tr>`).join("") || '<tr><td colspan="4" class="empty">Everything is up to date.</td></tr>'}</table>
      ${(x.pro_pending || []).length ? `<p class="muted small">Security fixes available only with Ubuntu Pro (free for personal use): <span class="mono">${esc([...new Set(x.pro_pending.map((p) => p.package))].join(", "))}</span></p>` : ""}`, { span: 24, h: "auto" });
    return R("sec-top", "Overview", top) + R("sec-find", "Findings", fpanel) + R("sec-img", "Container image vulnerabilities (CVE)", imgs) +
      R("sec-net", "Exposure & access", ports + access) + R("sec-hw", "Kernel & hardware", hw) + R("sec-upd", "Updates", updates);
  },
};
document.addEventListener("click", async (e) => {
  const t = e.target;
  if (t.id === "sec-refresh") { t.disabled = true; t.textContent = "Reviewing…"; await post("/api/security/refresh"); state.secBusy = true; setTimeout(() => render(true), 2500); }
  if (t.id === "sec-scan") {
    try { await post("/api/security/scan-images"); toast("Image scan started"); state.secBusy = true; render(true); } catch (err) { toast(err.message); }
  }
  if (t.id === "sec-scan-cancel") { await post("/api/security/scan-images/cancel"); toast("Cancelling after the current image…"); }
  if (t.dataset?.copy != null) {
    const txt = t.dataset.copy;
    const done = () => { t.textContent = "Copied"; setTimeout(() => (t.textContent = "Copy"), 1500); };
    // The dashboard is plain HTTP on the LAN, where navigator.clipboard is unavailable: fall back to a hidden textarea.
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(txt).then(done);
    else { const ta = document.createElement("textarea"); ta.value = txt; ta.style.position = "fixed"; ta.style.opacity = "0"; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove(); done(); }
  }
});

D.alerts = {
  title: "Recommendations", live: true,
  async render() {
    const recs = await api("/api/recommendations");
    const c = (s) => recs.filter((r) => r.severity === s).length;
    const top = stat({ title: "Critical", value: c("critical"), raw: c("critical"), th: [[0, "green"], [1, "red"]], span: 8, h: 1 }) +
      stat({ title: "Warning", value: c("warning"), raw: c("warning"), th: [[0, "green"], [1, "orange"]], span: 8, h: 1 }) +
      stat({ title: "Info", value: c("info"), color: "var(--cyan)", span: 8, h: 1 });
    const list = recs.map((r) => `<div class="ann ${esc(r.severity)}"><span class="bar"></span><div class="body"><div class="ttl">${esc(r.title)}</div>
      <div class="d">${esc(r.detail)}</div>${r.suggestion ? `<div class="d"><b>Suggestion:</b> ${esc(r.suggestion)}</div>` : ""}
      <details><summary>Evidence · confidence ${esc(r.confidence)} · since ${ago(r.first_seen)}</summary><pre class="log">${esc(JSON.stringify(r.evidence, null, 2))}</pre></details></div>
      <div class="tools">${chip(r.severity, r.severity)} ${chip("blue", r.category)} ${recTool(r.action)} <button class="btn sm" data-dismiss="${esc(r.id)}">Dismiss</button></div></div>`).join("") || '<div class="empty">No recommendations. All clear.</div>';
    return R("al-top", "Summary", top) + R("al-list", "Active recommendations", panel("Generated from collected evidence every 5 minutes. Nothing is applied automatically.", `<div class="scroll">${list}</div>`, { span: 24, h: 6 }));
  },
};
document.addEventListener("click", async (e) => { const id = e.target.dataset?.dismiss; if (id) { await post(`/api/recommendations/${encodeURIComponent(id)}/dismiss`); render(true); } });

D.audit = {
  title: "Audit log", live: false,
  async render() {
    const [rows, log] = await Promise.all([api("/api/audit"), api("/api/discovery-log?limit=150")]);
    const t = panel("Actions (append-only: the database rejects edits and deletions)", `<div class="scroll"><table class="t"><tr><th>#</th><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>Status</th><th>Summary</th><th>Before → after</th><th>Rollback</th></tr>
      ${rows.map((r) => `<tr><td>${r.id}</td><td class="muted">${new Date(r.ts * 1000).toLocaleString()}</td><td class="muted">${esc(r.user)}@${esc(r.client)}</td><td>${esc(r.action)}</td><td class="mono">${esc(r.target)}</td>
      <td>${chip(r.status === "done" ? "ok" : r.status === "failed" ? "crit" : "warn", r.status)}</td><td>${esc(r.summary)}</td>
      <td class="mono muted">${esc(JSON.stringify(r.before_state))} → ${esc(JSON.stringify(r.after_state))}<details><summary>result</summary>${esc(JSON.stringify(r.result))}</details></td><td class="muted">${esc(r.rollback || "")}</td></tr>`).join("") || '<tr><td colspan="9" class="empty">No actions yet.</td></tr>'}</table></div>`, { span: 24, h: 6 });
    const l = panel("Discovery log", `<div class="scroll"><table class="t"><tr><th>When</th><th>Collector</th><th>Level</th><th>Message</th></tr>${log.map((x) => `<tr><td class="muted">${new Date(x.ts * 1000).toLocaleString()}</td><td>${esc(x.collector)}</td><td>${chip(x.level === "error" ? "crit" : "muted", x.level)}</td><td class="mono">${esc(x.message)}</td></tr>`).join("")}</table></div>`, { span: 24, h: 5 });
    return R("au-a", "Audit", t) + R("au-d", "Collectors", l);
  },
};

D.settings = {
  title: "Settings", live: false,
  async render() {
    const s = await api("/api/settings"), c = s.config;
    const pw = panel("Dashboard password", `${s.initial_password_file_exists ? '<p class="note warn">You are still using the generated password. Set your own here.</p>' : ""}
      <form id="pw-form" autocomplete="on">
        <input type="text" name="username" value="admin" autocomplete="username" hidden>
        <label class="muted small" for="pw-cur">Current password</label>
        <input class="in" type="password" id="pw-cur" autocomplete="current-password" required>
        <label class="muted small" for="pw-new">New password (at least 10 characters)</label>
        <input class="in" type="password" id="pw-new" autocomplete="new-password" minlength="10" required>
        <label class="muted small" for="pw-new2">Repeat new password</label>
        <input class="in" type="password" id="pw-new2" autocomplete="new-password" minlength="10" required>
        <div class="dup-actions"><button class="btn primary" type="submit" id="pw-save">Change password</button><span id="pw-msg" class="small" role="status"></span></div>
      </form>`, { span: 8, h: "auto" });
    const prot = panel("Protection", `<p class="muted" style="margin-top:0">Protected paths (never scanned, quarantined or changed):</p>${c.protection.protected_paths.map((p) => `<div class="mono">${esc(p)}</div>`).join("")}
      <p class="muted">Protected anywhere: ${esc(c.protection.protected_patterns.join(", "))}</p><p class="muted">Protected services: <span class="mono">${esc(c.protection.protected_units.join(", "))}</span></p>
      <p class="muted">Edit <span class="mono">${esc(s.config_file)}</span>, then <span class="mono">systemctl --user restart guardian</span>.</p>`, { span: 16, h: "auto" });
    const load = panel("Load protection", `<div class="kv">
      <div>Busy when</div><div>load &gt; ${c.governor.busy_load_per_cpu}/CPU, CPU &gt; ${c.governor.busy_cpu_percent}%, RAM free &lt; ${c.governor.busy_mem_available_percent}%, I/O pressure &gt; ${c.governor.busy_io_pressure}%, or Immich processing</div>
      <div>While busy</div><div>heavy checks wait (up to ${c.governor.max_defer}× their interval); duplicate scans pause</div>
      <div>Hard limits</div><div>systemd CPUQuota 25%, MemoryMax 400 MB, idle I/O class, nice 10</div>
      <div>Scan read rate</div><div>${c.duplicates.read_rate_mb_s} MB/s</div>
      <div>Root helper</div><div>${s.executor ? chip("ok", "installed") : chip("warn", "not installed")} ${s.executor ? "" : `<span class="mono">${esc(s.executor_install)}</span>`}</div>
      <div>Immich API key</div><div>${c.immich.api_key ? "configured" : "not set"}</div><div>Backup monitoring</div><div class="mono">${c.backup.unit || c.backup.drive_uuid ? esc([c.backup.unit && c.backup.unit + ".service", c.backup.drive_uuid && "drive " + c.backup.drive_uuid].filter(Boolean).join(" · ")) : "off (optional, see README)"}</div>
      <div>Install folder</div><div class="mono">${esc(s.install_dir)}</div></div>`, { span: 10, h: 5 });
    const coll = panel("Collectors", `<div class="scroll"><table class="t"><tr><th>Task</th><th class="n">Every</th><th class="n">Last run</th><th>Type</th><th>Status</th></tr>
      ${s.scheduler.map((t) => `<tr><td>${esc(t.name)}</td><td class="n">${t.interval >= 3600 ? t.interval / 3600 + " h" : t.interval + " s"}</td><td class="n">${t.last_ms} ms</td><td>${t.heavy ? "heavy" : "light"}</td>
      <td>${t.last_error ? chip("crit", "error") + ' <span class="muted">' + esc(t.last_error) + "</span>" : t.deferred ? chip("warn", "deferred ×" + t.deferred) : chip("ok", t.runs + " runs")}</td></tr>`).join("")}</table></div>`, { span: 14, h: 5 });
    return R("se-a", "Access & protection", pw + prot) + R("se-b", "Guardian", load + coll);
  },
};
document.addEventListener("submit", async (e) => {
  if (e.target.id !== "pw-form") return;
  e.preventDefault();
  const msg = $("#pw-msg"), btn = $("#pw-save");
  const say = (text, ok) => { msg.textContent = text; msg.style.color = ok ? "var(--green)" : "var(--red)"; };
  const cur = $("#pw-cur").value, nw = $("#pw-new").value.trim(), nw2 = $("#pw-new2").value.trim();
  if (!cur) return say("Enter your current password.");
  if (nw.length < 10) return say("The new password must be at least 10 characters.");
  if (nw !== nw2) return say("The two new passwords do not match.");
  if (nw === cur) return say("The new password is the same as the current one.");
  btn.disabled = true; btn.textContent = "Saving…"; say("", true);
  try {
    await post("/api/password", { current: cur, new: nw });
    say("Password changed. Taking you to the login page…", true);
    setTimeout(() => (location.href = "/login"), 1800);
  } catch (err) {
    say(err.message); btn.disabled = false; btn.textContent = "Change password";
  }
});

// ------------------------------------------------------------------ variables bar
function renderVars(dash) {
  const v = dash.vars ? dash.vars() : null;
  $("#vars").innerHTML = v ? Object.entries(v).map(([k, d]) => `<div class="var"><label for="var-${k}">${esc(d.label)}</label>${d.text
    ? `<input id="var-${k}" data-var="${k}" value="${esc(state.vars[k] || "")}" placeholder="type to filter">`
    : `<select id="var-${k}" data-var="${k}">${d.options.map((o) => `<option ${state.vars[k] === o ? "selected" : ""}>${esc(o)}</option>`).join("")}</select>`}</div>`).join("") : "";
  $("#vars").style.display = v ? "" : "none";
}
document.addEventListener("change", (e) => { const k = e.target.dataset?.var; if (k && e.target.tagName === "SELECT") { state.vars[k] = e.target.value; store.set("vars", state.vars); render(false); } });
document.addEventListener("input", (e) => {
  const k = e.target.dataset?.var; if (!k || e.target.tagName !== "INPUT") return;
  state.vars[k] = e.target.value; clearTimeout(window._vq); window._vq = setTimeout(() => render(false), 250);
});

// ------------------------------------------------------------------ router & refresh
let timer = null, busy = false, again = false;
const where = () => { const [, page = "server", arg] = (location.hash || "#/server").split("/"); return { page: D[page] ? page : "server", arg }; };
async function render(showDot) {
  // One render at a time; a request that arrives meanwhile runs right after (never dropped).
  if (busy) { again = true; return; }
  busy = true; again = false;
  const { page, arg } = where(), dash = D[page];
  if (state.page !== page || state.arg !== arg) {
    state.page = page; state.arg = arg;
    renderVars(dash);
    document.querySelectorAll("[data-nav]").forEach((a) => a.classList.toggle("active", a.dataset.nav === page));
    $("#crumb").innerHTML = `Home › Dashboards › <b>${esc(dash.title)}</b>`;
    document.title = `${dash.title} · Guardian`;
  }
  try {
    charts.clear();
    const html = await dash.render(arg);
    const now = where();
    if (now.page !== page || now.arg !== arg) again = true;   // user navigated meanwhile: discard
    else if (!dlg.open) $("#main").innerHTML = html;
    // Container names are only known after the first Docker render: refresh the selector once.
    const sel = $("#var-container");
    if (page === "docker" && sel && sel.options.length !== (state.containerNames || []).length + 1) renderVars(dash);
    if (showDot) { const d = $("#dot"); d.classList.remove("pulse"); void d.offsetWidth; d.classList.add("pulse"); }
  } catch (e) {
    $("#main").innerHTML = `<div class="g"><div class="p s24"><div class="pb">Could not load: ${esc(e.message)}</div></div></div>`;
  } finally { busy = false; }
  if (again) return render(false);
  schedule();
}
function schedule() {
  clearTimeout(timer);
  const { page, arg } = where();
  // Live dashboards refresh on the chosen interval; forms and detail pages only while a scan runs.
  const live = (D[page].live && !arg) || (page === "duplicates" && !arg && state.dupRunning) || (page === "security" && state.secBusy);
  const every = page === "duplicates" || page === "security" ? 3 : state.every;
  if (every > 0 && live) timer = setTimeout(() => { if (document.visibilityState === "visible") render(true); else schedule(); }, every * 1000);
}
document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible" && state.every > 0 && D[where().page].live) render(true); });
window.addEventListener("hashchange", () => { if (dlg.open) dlg.close(); render(false); });
render(false);
