"use strict";
// Giao diện LinuxSign. Mọi thao tác token/ký đều gọi lệnh Rust qua Tauri `invoke`.

const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);
const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtDate = (iso) => (iso ? new Date(iso).toLocaleDateString("vi-VN", { day: "2-digit", month: "2-digit", year: "numeric" }) : "—");
const fileName = (p) => p.split(/[\\/]/).pop();

// ------------------------------------------------------------------ icons
const ICONS = {
  grid: '<path d="M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z"/>',
  pen: '<path d="M4 20h4L19 9l-4-4L4 16v4zM14 6l4 4"/>',
  pulse: '<path d="M3 12h4l2-6 4 12 2-6h6"/>',
  book: '<path d="M5 4h10a3 3 0 0 1 3 3v13H8a3 3 0 0 1-3-3V4zM5 17a3 3 0 0 1 3-3h10"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
  refresh: '<path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7"/>',
  file: '<path d="M14 3H6v18h12V7l-4-4zM14 3v4h4"/>',
  usb: '<path d="M8 3h8v6H8zM6 9h12v8a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V9zM10 5h1M13 5h1"/>',
  cal: '<rect x="4" y="5" width="16" height="16" rx="2"/><path d="M4 10h16M9 3v4M15 3v4"/>',
  download: '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5v.5"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3M15 8l2 2"/>',
  pin: '<path d="M12 21s-7-6.2-7-11.5A7 7 0 0 1 19 9.5C19 14.8 12 21 12 21z"/><circle cx="12" cy="9.5" r="2.5"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  plug: '<path d="M9 3v5M15 3v5M6 8h12v3a6 6 0 0 1-12 0V8zM12 17v4"/>',
  shield: '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z"/>',
  folder: '<path d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6z"/>',
  block: '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',
  tray: '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M3 13h18M16 15.5h2M8 21h8"/>',
  power: '<path d="M12 3v9M7 6.3a7 7 0 1 0 10 0"/>',
  font: '<path d="M4 20l6-16h1l6 16M6.5 14h8"/><path d="M17 12h4M19 10v6"/>',
};
function icon(name) {
  return `<i data-icon="${name}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">${ICONS[name] || ""}</svg></i>`;
}
function hydrateIcons(root = document) {
  $$("i[data-icon]", root).forEach((el) => { if (!el.firstChild) el.outerHTML = icon(el.dataset.icon); });
}

function toast(msg, kind = "") {
  const t = document.createElement("div");
  t.className = `toast ${kind}`;
  t.textContent = msg;
  $("#toasts").append(t);
  setTimeout(() => t.remove(), kind === "danger" ? 7000 : 4000);
}

// ------------------------------------------------------------------ state
const state = {
  report: { tokens: [], modules: [] },
  warnDays: 30,
  config: null,
  scanning: false,
  knownTokens: null,
  sign: { mode: "pdf", input: null, output: null, pages: [[595, 842]], preselect: null },
};

function certStatus(c) {
  const now = Date.now() / 1000;
  if (c.not_after_ts < now) return "expired";
  if (new Date(c.not_before).getTime() / 1000 > now) return "not_yet_valid";
  if (c.days_left <= state.warnDays) return "expiring";
  return "valid";
}
const STATUS = {
  valid: { label: "Còn hạn", cls: "ok" },
  expiring: { label: "Sắp hết hạn", cls: "warn" },
  expired: { label: "Đã hết hạn", cls: "danger" },
  not_yet_valid: { label: "Chưa hiệu lực", cls: "warn" },
};
const allCerts = () => state.report.tokens.flatMap((t) => t.certificates.map((c) => ({ token: t, cert: c })));

// ------------------------------------------------------------------ navigation
function go(page) {
  $$("nav button").forEach((b) => b.classList.toggle("active", b.dataset.page === page));
  $$(".page").forEach((p) => p.classList.toggle("active", p.id === `page-${page}`));
  if (page === "sign") renderCertSelect();
  if (page === "settings") loadSettings();
}
$$("nav button").forEach((b) => b.addEventListener("click", () => go(b.dataset.page)));
document.addEventListener("click", (e) => { if (e.target.matches("[data-close]")) e.target.closest("dialog").close(); });

// ------------------------------------------------------------------ scan & overview
async function scan(deep = false, quiet = false) {
  if (state.scanning) return;
  state.scanning = true;
  if (!quiet) $("#scan-time").innerHTML = '<span class="spin"></span> Đang quét…';
  try {
    const r = await invoke("scan_tokens", { deep });
    state.report = r.report;
    state.warnDays = r.warn_days;
    $("#scan-time").textContent = `Cập nhật lúc ${r.scanned_at}`;
    detectPlug();
    renderOverview();
    if ($("#page-sign").classList.contains("active")) renderCertSelect();
  } catch (e) {
    $("#scan-time").textContent = "Lỗi khi quét";
    if (!quiet) toast(String(e), "danger");
  } finally {
    state.scanning = false;
  }
}

function detectPlug() {
  const now = new Map(state.report.tokens.map((t) => [t.token_id, t.label]));
  if (state.knownTokens) {
    for (const [id, label] of now) if (!state.knownTokens.has(id)) toast(`Đã nhận token “${label}”`);
    for (const [id, label] of state.knownTokens) if (!now.has(id)) toast(`Đã rút token “${label}”`);
  }
  state.knownTokens = now;
}

function initials(name) {
  const w = name.replace(/^(CÔNG TY|CONG TY|CTY)\s+(TNHH|CP|CỔ PHẦN)?\s*/i, "").split(/\s+/).filter(Boolean);
  return ((w[0]?.[0] || "?") + (w.length > 1 ? w[w.length - 1][0] : "")).toUpperCase();
}

function renderOverview() {
  const certs = allCerts().map((x) => certStatus(x.cert));
  const count = (s) => certs.filter((x) => x === s).length;
  $("#stats").innerHTML = [
    ["", state.report.tokens.length, "Token đang cắm"],
    ["ok", count("valid"), "Chứng thư còn hạn"],
    ["warn", count("expiring") + count("not_yet_valid"), `Sắp hết hạn (≤ ${state.warnDays} ngày)`],
    ["danger", count("expired"), "Đã hết hạn"],
  ].map(([c, n, l]) => `<div class="stat ${c}"><b>${n}</b><span>${l}</span></div>`).join("");

  if (!state.report.tokens.length) {
    $("#tokens").innerHTML = `
      <div class="card empty">
        <div class="big-icon">${icon("usb")}</div>
        <h3>Chưa thấy USB Token nào</h3>
        <ol>
          <li>Cắm USB Token chữ ký số vào máy.</li>
          <li>Cài driver của nhà cung cấp chữ ký số (hoặc OpenSC).</li>
          <li>Trên Linux: bật dịch vụ <code>pcscd</code>.</li>
        </ol>
        <div><button class="btn primary" id="go-doctor">${icon("pulse")}Chạy chẩn đoán</button>
        <button class="btn ghost" id="go-guide">${icon("book")}Xem hướng dẫn</button></div>
      </div>`;
    $("#go-doctor").onclick = () => { go("doctor"); runDoctor(); };
    $("#go-guide").onclick = () => go("guide");
    return;
  }

  $("#tokens").innerHTML = state.report.tokens.map((t) => {
    const badges = [];
    if (t.pin_locked) badges.push('<span class="badge danger">PIN đã bị khóa</span>');
    else if (t.pin_final_try) badges.push('<span class="badge danger">Còn 1 lần nhập PIN</span>');
    else if (t.pin_count_low) badges.push('<span class="badge warn">Đã nhập sai PIN</span>');
    if (t.protected_auth_path) badges.push('<span class="badge gray">PIN trên thiết bị</span>');
    badges.push(`<span class="badge gray" title="${esc(t.routes[0].module)}">${esc(t.routes[0].vendor.split("(")[0].trim())}</span>`);
    return `
    <div class="card token">
      <div class="token-head">
        <div class="usb">${icon("usb")}</div>
        <div><h3>${esc(t.label || "USB Token")}</h3>
          <div class="meta">${esc(t.manufacturer)} ${esc(t.model)} · Serial ${esc(t.serial)}</div></div>
        <div class="badges">${badges.join("")}</div>
      </div>
      ${t.certificates.map((c) => certRow(t, c)).join("")}
    </div>`;
  }).join("");

  $$("[data-act]").forEach((b) => b.addEventListener("click", () => certAction(b.dataset.act, b.dataset.cert)));
}

function certRow(t, c) {
  const st = STATUS[certStatus(c)];
  const start = new Date(c.not_before).getTime(), end = new Date(c.not_after).getTime();
  const left = Math.max(0, Math.min(100, ((end - Date.now()) / (end - start)) * 100));
  const days = c.days_left >= 0
    ? `${c.days_left.toLocaleString("vi-VN")} <small>ngày</small>`
    : `${(-c.days_left).toLocaleString("vi-VN")} <small>ngày trước</small>`;
  const ids = [
    c.tax_code ? ["Mã số thuế", c.tax_code] : null,
    c.personal_id ? ["Định danh", c.personal_id] : null,
    c.subject_o && c.subject_o !== c.subject_cn ? ["Tổ chức", c.subject_o] : null,
    ["Nhà cung cấp", c.issuer_o && c.issuer_o !== c.issuer_cn ? `${c.issuer_cn} (${c.issuer_o})` : c.issuer_cn],
    ["Hiệu lực", `${fmtDate(c.not_before)} → ${fmtDate(c.not_after)}`],
    ["Số serial", c.serial_hex.toUpperCase()],
  ].filter(Boolean);
  return `
    <div class="cert">
      <div class="avatar">${esc(initials(c.subject_cn))}</div>
      <div>
        <h4>${esc(c.subject_cn)}</h4>
        <span class="badge ${st.cls}">${st.label}</span>
        <dl class="kv">${ids.map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join("")}</dl>
        <div class="actions">
          <button class="btn small" data-act="sign-pdf" data-cert="${c.cert_id}" ${c.days_left < 0 ? "disabled" : ""}>${icon("pen")}Ký PDF</button>
          <button class="btn small ghost" data-act="sign-file" data-cert="${c.cert_id}" ${c.days_left < 0 ? "disabled" : ""}>${icon("file")}Ký file</button>
          <button class="btn small ghost" data-act="ics" data-cert="${c.cert_id}" title="Thêm ngày hết hạn vào lịch">${icon("cal")}Nhắc gia hạn</button>
          <button class="btn small ghost" data-act="export" data-cert="${c.cert_id}">${icon("download")}Xuất chứng thư</button>
          <button class="btn small ghost" data-act="detail" data-cert="${c.cert_id}">${icon("info")}Chi tiết</button>
        </div>
      </div>
      <div class="expiry ${st.cls}">
        <div class="muted small">${c.days_left >= 0 ? "Còn lại" : "Đã hết hạn"}</div>
        <div class="days">${days}</div>
        <div class="bar"><div style="width:${left.toFixed(1)}%"></div></div>
        <div class="muted small">Hết hạn ${fmtDate(c.not_after)}</div>
      </div>
    </div>`;
}

async function certAction(act, certId) {
  const found = allCerts().find((x) => x.cert.cert_id === certId);
  if (!found) return;
  const { token, cert } = found;
  const safe = cert.subject_cn.replace(/[^\p{L}\p{N}]+/gu, "_").slice(0, 40);
  try {
    if (act === "sign-pdf" || act === "sign-file") {
      state.sign.preselect = certId;
      setMode(act === "sign-pdf" ? "pdf" : "file");
      go("sign");
    } else if (act === "export") {
      const path = await invoke("save_file", { defaultPath: `${safe}.cer`, ext: "cer" });
      if (path) { await invoke("export_cert", { certId, path }); toast(`Đã xuất chứng thư: ${fileName(path)}`); }
    } else if (act === "ics") {
      const path = await invoke("save_file", { defaultPath: `het-han-chu-ky-so_${safe}.ics`, ext: "ics" });
      if (path) {
        await invoke("export_ics", { certId, path, remindDays: state.warnDays });
        toast("Đã tạo nhắc lịch. Mở file .ics để thêm vào Lịch (Google, Outlook, Thunderbird…)");
        invoke("open_path", { path, reveal: true }).catch(() => {});
      }
    } else if (act === "detail") {
      showDetail(token, cert);
    }
  } catch (e) {
    toast(String(e), "danger");
  }
}

function showDetail(t, c) {
  const rows = [
    ["Chủ thể (Subject)", c.subject],
    ...c.subject_fields.map(([k, v]) => [`  ${k}`, v]),
    ["Nhà cung cấp", c.issuer_cn],
    ["Số serial", c.serial_hex.toUpperCase()],
    ["Hiệu lực từ", new Date(c.not_before).toLocaleString("vi-VN")],
    ["Hiệu lực đến", new Date(c.not_after).toLocaleString("vi-VN")],
    ["Khóa", `${c.key_type} ${c.key_size || ""} bit`],
    ["Mục đích", c.can_sign ? "Ký số" : "Không dùng để ký"],
    ["Thumbprint SHA-1", c.cert_id.toUpperCase()],
    ["CKA_ID / nhãn", `${c.cka_id || "—"} / ${c.label || "—"}`],
    ["Token", `${t.label} (${t.manufacturer} ${t.model}, serial ${t.serial})`],
    ["Driver chính", t.routes[0].module],
    ...t.routes.slice(1).map((r) => ["Driver dự phòng", r.module]),
    ["Độ dài PIN", t.max_pin_len ? `${t.min_pin_len}–${t.max_pin_len} ký tự` : "—"],
    ["Cơ chế hỗ trợ", t.mechanisms.length ? t.mechanisms.join(", ") : "—"],
  ];
  $("#detail-body").innerHTML = `<h3>${esc(c.subject_cn)}</h3><table>${rows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join("")}</table>`;
  $("#detail-dialog").showModal();
}

$("#btn-rescan").addEventListener("click", () => scan(true));

// ------------------------------------------------------------------ sign page
function setMode(mode) {
  state.sign.mode = mode;
  $$("#sign-mode button").forEach((b) => b.classList.toggle("active", b.dataset.mode === mode));
  $("#pdf-opts").hidden = mode !== "pdf";
  $("#xml-opts").hidden = mode !== "xml";
  $("#file-opts").hidden = mode !== "file";
  $("#use-tsa").closest("label").hidden = mode === "xml";
  $("#tsa-hint").hidden = mode === "xml";
  $(".preview-card h3").textContent = mode === "pdf" ? "Xem trước vị trí" : "Kết quả";
  $("#page-preview").hidden = mode !== "pdf";
  $("#preview-hint").hidden = mode !== "pdf";
  const okExt = mode === "pdf" ? /\.pdf$/i : mode === "xml" ? /\.xml$/i : /./;
  if (state.sign.input && okExt.test(state.sign.input)) setOutputDefault();
  else { state.sign.input = null; $("#input-path").textContent = "Chưa chọn file"; state.sign.output = null; $("#output-path").textContent = "—"; }
  updateSignButton();
}
$$("#sign-mode button").forEach((b) => b.addEventListener("click", () => setMode(b.dataset.mode)));

function renderCertSelect() {
  const sel = $("#cert-select");
  const prev = state.sign.preselect || sel.value;
  const usable = allCerts().filter((x) => x.cert.days_left >= 0 && x.cert.can_sign);
  sel.innerHTML = usable.length
    ? usable.map(({ token, cert }) => `<option value="${cert.cert_id}">${esc(cert.subject_cn)}${cert.tax_code ? " · MST " + esc(cert.tax_code) : ""} — ${esc(token.label)}</option>`).join("")
    : '<option value="">(Không có chứng thư còn hạn: hãy cắm token)</option>';
  if (usable.some((x) => x.cert.cert_id === prev)) sel.value = prev;
  state.sign.preselect = null;
  certHint();
  const tsa = state.config?.tsa_url;
  $("#use-tsa").disabled = !tsa;
  $("#tsa-hint").innerHTML = tsa ? `Máy chủ: <code>${esc(tsa)}</code>` : "Chưa cấu hình máy chủ TSA: thêm trong Cài đặt.";
  if (!tsa) $("#use-tsa").checked = false;
  if (!$("#reason").value && state.config?.default_reason) $("#reason").value = state.config.default_reason;
  if (!$("#location").value && state.config?.default_location) $("#location").value = state.config.default_location;
  updateSignButton();
}
function certHint() {
  const f = allCerts().find((x) => x.cert.cert_id === $("#cert-select").value);
  if (!f) { $("#cert-hint").textContent = ""; return; }
  const st = certStatus(f.cert);
  $("#cert-hint").innerHTML = `Hết hạn ${fmtDate(f.cert.not_after)} (còn ${f.cert.days_left} ngày)` + (st === "expiring" ? ' · <b style="color:var(--warn)">nên gia hạn sớm</b>' : "");
}
$("#cert-select").addEventListener("change", certHint);

function setOutputDefault() {
  const p = state.sign.input;
  const m = state.sign.mode;
  state.sign.output = m === "pdf" ? p.replace(/(\.pdf)?$/i, "_signed.pdf") : m === "xml" ? p.replace(/(\.xml)?$/i, "_signed.xml") : `${p}.p7s`;
  $("#output-path").textContent = state.sign.output;
}

$("#pick-input").addEventListener("click", async () => {
  const p = await invoke("pick_file", { kind: state.sign.mode === "file" ? "any" : state.sign.mode });
  if (!p) return;
  state.sign.input = p;
  $("#input-path").textContent = p;
  $("#input-path").classList.remove("muted");
  setOutputDefault();
  $("#sign-result").innerHTML = "";
  if (state.sign.mode === "pdf") {
    try {
      state.sign.pages = await invoke("pdf_pages", { path: p });
      $("#page-select").innerHTML = state.sign.pages.map((_, i) => `<option value="${i + 1}">${i + 1}</option>`).join("");
      $("#page-select").value = String(state.sign.pages.length >= 1 ? state.sign.pages.length : 1); // mặc định: trang cuối
      updatePreview();
    } catch (e) { toast(String(e), "danger"); }
  }
  updateSignButton();
});

$("#pick-output").addEventListener("click", async () => {
  if (!state.sign.output) return;
  const p = await invoke("save_file", { defaultPath: state.sign.output, ext: { pdf: "pdf", xml: "xml", file: "p7s" }[state.sign.mode] });
  if (p) { state.sign.output = p; $("#output-path").textContent = p; }
});

function sigRect() {
  const page = Number($("#page-select").value) || 1;
  const [w, h] = state.sign.pages[page - 1] || [595, 842];
  const bw = Math.min(220, w * 0.42), bh = 72, m = 36;
  const pos = $("#pos-select").value;
  const x1 = pos.endsWith("r") ? w - m - bw : m;
  const y1 = pos.startsWith("b") ? m : h - m - bh;
  return { page, rect: [x1, y1, x1 + bw, y1 + bh], size: [w, h] };
}
function updatePreview() {
  const box = $("#sig-box");
  box.hidden = !$("#visible").checked;
  $("#visible-opts").hidden = !$("#visible").checked;
  const { rect, size } = sigRect();
  const pv = $("#page-preview");
  pv.style.aspectRatio = `${size[0]} / ${size[1]}`;
  box.style.left = `${(rect[0] / size[0]) * 100}%`;
  box.style.width = `${((rect[2] - rect[0]) / size[0]) * 100}%`;
  box.style.bottom = `${(rect[1] / size[1]) * 100}%`;
  box.style.height = `${((rect[3] - rect[1]) / size[1]) * 100}%`;
}
["#visible", "#pos-select", "#page-select"].forEach((s) => $(s).addEventListener("change", updatePreview));

function updateSignButton() {
  $("#btn-sign").disabled = !(state.sign.input && $("#cert-select").value);
}

// ---------- PIN dialog
function askPin(token, error) {
  return new Promise((resolve) => {
    const dlg = $("#pin-dialog");
    $("#pin-token").textContent = `Token: ${token.label} (${token.manufacturer})`;
    const warn = token.pin_final_try ? "Chỉ còn 1 lần nhập: nhập sai nữa token sẽ bị khóa!" : token.pin_count_low ? "Đã có lần nhập sai PIN trước đó. Hãy cẩn thận." : "";
    $("#pin-warn").hidden = !warn;
    $("#pin-warn").textContent = warn;
    $("#pin-error").hidden = !error;
    $("#pin-error").textContent = error || "";
    const inp = $("#pin-input");
    inp.value = "";
    inp.hidden = token.protected_auth_path;
    if (token.protected_auth_path) $("#pin-token").textContent += ". Nhập PIN trên bàn phím của thiết bị sau khi bấm Ký.";
    dlg.returnValue = "";
    dlg.showModal();
    inp.focus();
    dlg.addEventListener("close", () => resolve(dlg.returnValue === "ok" ? (token.protected_auth_path ? null : inp.value) : undefined), { once: true });
  });
}

$("#btn-sign").addEventListener("click", async () => {
  const certId = $("#cert-select").value;
  const found = allCerts().find((x) => x.cert.cert_id === certId);
  if (!found) return;
  if (found.token.pin_locked) { toast("Token đã bị khóa PIN: liên hệ nhà cung cấp chữ ký số để mở khóa.", "danger"); return; }
  let error = null;
  for (;;) {
    const pin = await askPin(found.token, error);
    if (pin === undefined) return;
    if (pin !== null && !pin) { error = "Chưa nhập PIN."; continue; }
    const btn = $("#btn-sign");
    btn.disabled = true;
    btn.innerHTML = '<span class="spin"></span> Đang ký…';
    try {
      const common = { certId, pin, input: state.sign.input, output: state.sign.output, useTsa: $("#use-tsa").checked };
      const req = state.sign.mode === "pdf"
        ? { cert_id: certId, pin, input: common.input, output: common.output, reason: $("#reason").value, location: $("#location").value,
            visible: $("#visible").checked ? (({ page, rect }) => ({ page, rect }))(sigRect()) : null, use_tsa: common.useTsa }
        : { cert_id: certId, pin, input: common.input, output: common.output, attached: $("#attached").checked, use_tsa: common.useTsa };
      if (state.sign.mode === "xml") {
        Object.assign(req, { profile: $("#xml-profile").value, reference_id: $("#xml-ref").value.trim() || null, parent_path: $("#xml-parent").value.trim() || null });
        delete req.attached; delete req.use_tsa;
      }
      const res = await invoke({ pdf: "sign_pdf", xml: "sign_xml", file: "sign_file" }[state.sign.mode], { req });
      showResult(res);
      toast("Ký số thành công");
      return;
    } catch (e) {
      const msg = String(e);
      if (msg.startsWith("PIN:")) { error = msg.slice(4); scan(false, true); continue; }
      $("#sign-result").innerHTML = `<div class="alert danger">${esc(msg)}</div>`;
      return;
    } finally {
      btn.innerHTML = `${icon("pen")}Ký số`;
      updateSignButton();
    }
  }
});

function showResult(res) {
  $("#sign-result").innerHTML = `
    <div class="alert ok"><b>Đã ký thành công</b><br>${esc(fileName(res.output))}<br><span class="small">${esc(res.detail)}</span></div>
    <div class="actions"><button class="btn small" id="open-out">${icon("file")}Mở file</button>
    <button class="btn small ghost" id="reveal-out">Mở thư mục</button></div>`;
  $("#open-out").onclick = () => invoke("open_path", { path: res.output, reveal: false }).catch((e) => toast(String(e), "danger"));
  $("#reveal-out").onclick = () => invoke("open_path", { path: res.output, reveal: true }).catch((e) => toast(String(e), "danger"));
}

// ------------------------------------------------------------------ doctor
async function runDoctor() {
  const out = $("#doctor-out");
  out.innerHTML = '<div class="card empty"><span class="spin"></span> Đang kiểm tra…</div>';
  try {
    const r = await invoke("run_doctor");
    const row = (ok, title, desc) => `<div class="check-row"><div class="dot ${ok === true ? "ok" : ok === null ? "warn" : "danger"}">${ok === true ? "✓" : ok === null ? "!" : "✕"}</div><div><b>${title}</b><div class="muted small">${desc}</div></div></div>`;
    const checks = [];
    if (r.pcscd_running !== null) checks.push(row(r.pcscd_running, "Dịch vụ smart card (pcscd)", r.pcscd_running ? "Đang chạy" : "Chưa chạy: token sẽ không được nhận"));
    if (r.os.startsWith("linux")) checks.push(row(r.usb_devices.length > 0, "Thiết bị USB Token", r.usb_devices.length ? r.usb_devices.map((d) => `${esc(d.id)} ${esc(d.product)} (${esc(d.vendor_hint)})`).join("<br>") : "Không thấy thiết bị smart card nào đang cắm"));
    const okMods = r.modules.filter((m) => !m.error).length;
    checks.push(row(okMods > 0 ? true : r.modules.length ? null : false, "Driver PKCS#11", `${r.modules.length} driver tìm thấy, ${okMods} hoạt động`));
    checks.push(row(r.certificate_count > 0, "Token và chứng thư", `${r.token_count} token, ${r.certificate_count} chứng thư`));
    out.innerHTML = `
      <div class="card"><div class="checks">${checks.join("")}</div>
        ${r.advice.length ? `<h3>Khuyến nghị</h3>${r.advice.map((a) => `<div class="alert warn">${esc(a)}</div>`).join("")}` : '<div class="alert ok">Hệ thống sẵn sàng để ký số.</div>'}
      </div>
      <div class="card" style="margin-top:16px"><h3>Driver PKCS#11 (${r.modules.length})</h3>
        ${r.modules.length ? `<table><tr><th>Đường dẫn</th><th>Hãng</th><th>Nguồn</th><th>Trạng thái</th></tr>
          ${r.modules.map((m) => `<tr><td><code>${esc(m.path)}</code>${m.library ? `<div class="muted small">${esc(m.library.description)} ${esc(m.library.version)}</div>` : ""}</td><td>${esc(m.vendor)}</td><td>${esc(m.source)}</td>
          <td>${m.error ? `<span class="badge danger">Lỗi</span><div class="small">${esc(m.error)}</div>` : `<span class="badge ok">${m.token_count} token</span>`}</td></tr>`).join("")}</table>`
          : '<p class="muted">Không có driver nào.</p>'}
        <p class="muted small">Phiên bản ${esc(r.version)} · ${esc(r.os)}</p>
      </div>`;
  } catch (e) {
    out.innerHTML = `<div class="alert danger">${esc(e)}</div>`;
  }
}
$("#btn-doctor").addEventListener("click", runDoctor);

// ------------------------------------------------------------------ guide
const GUIDE = [
  ["🚀", "Bắt đầu nhanh", `
    <ol>
      <li>Cắm USB Token chữ ký số vào máy.</li>
      <li>Mở trang <b>Tổng quan</b>: token và chứng thư hiện ra tự động sau vài giây, kèm số ngày còn hạn.</li>
      <li>Bấm <b>Ký PDF</b> trên chứng thư, chọn file, nhập PIN: xong.</li>
    </ol>
    <p>Nếu không thấy token, mở trang <b>Chẩn đoán</b>: ứng dụng sẽ chỉ ra thiếu gì (dịch vụ, driver, thiết bị).</p>`],
  ["🐧", "Cài đặt trên Linux", `
    <p><b>Ubuntu / Debian / Linux Mint:</b></p>
    <pre>sudo apt install pcscd libccid opensc
sudo systemctl enable --now pcscd.socket</pre>
    <p><b>Fedora / RHEL:</b></p>
    <pre>sudo dnf install pcsc-lite pcsc-lite-ccid opensc
sudo systemctl enable --now pcscd.socket</pre>
    <p>Sau đó cài <b>driver Linux của nhà cung cấp chữ ký số</b> (thường là file <code>.deb</code>/<code>.rpm</code>, hỏi bộ phận hỗ trợ của nhà cung cấp). LinuxSign tự tìm mọi driver PKCS#11 đã cài, không cần cấu hình.</p>
    <p>Nếu nhà cung cấp không có driver Linux, OpenSC (đã cài ở trên) hỗ trợ sẵn nhiều loại chip phổ biến.</p>`],
  ["🪟", "Cài đặt trên Windows / macOS", `
    <p>Cài phần mềm/driver token của nhà cung cấp chữ ký số như bình thường (bộ cài đi kèm token). LinuxSign dùng chung driver đó, không cần thêm gì.</p>
    <p>Trên macOS, có thể cài thêm OpenSC: <code>brew install opensc</code>.</p>`],
  ["✍️", "Ký tài liệu PDF", `
    <ol>
      <li>Vào <b>Ký số → Tài liệu PDF</b>, chọn file.</li>
      <li>Chọn chứng thư, nhập lý do và nơi ký (không bắt buộc).</li>
      <li>Chọn trang và vị trí khung chữ ký, xem trước ở khung bên phải.</li>
      <li>Bật <b>Dấu thời gian</b> nếu văn bản cần lưu trữ lâu dài (cần cấu hình máy chủ TSA trong Cài đặt).</li>
      <li>Bấm <b>Ký số</b>, nhập PIN. File được lưu thành <code>tên_signed.pdf</code>.</li>
    </ol>
    <p>Chữ ký theo chuẩn <b>PAdES</b> (ETSI.CAdES.detached), được Adobe Acrobat/Reader, Foxit, Okular và các hệ thống tiếp nhận văn bản điện tử công nhận. Một file có thể ký nhiều lần (nhiều người ký); chữ ký trước vẫn hợp lệ.</p>`],
  ["🧾", "Ký XML: hóa đơn điện tử, tờ khai thuế", `
    <p>Vào <b>Ký số → XML / Hóa đơn</b>, chọn file <code>.xml</code> và loại chữ ký:</p>
    <ul>
      <li><b>Hóa đơn điện tử</b>: ký phần dữ liệu <code>&lt;DLHDon Id="…"&gt;</code>, đặt chữ ký người bán trong <code>DSCKS/NBan</code>, kèm thời điểm ký (<code>SigningTime</code>). Chuẩn XMLDSig, SHA-256, chuẩn hóa C14N.</li>
      <li><b>Tờ khai / văn bản XML</b>: chữ ký enveloped cho cả văn bản (hoặc phần tử có Id chỉ định), đặt ở vị trí tùy chọn, ví dụ <code>CKyDTu</code>.</li>
      <li><b>XAdES-BES</b>: chữ ký điện tử nâng cao, có thời điểm ký và thông tin chứng thư được ký kèm.</li>
    </ul>
    <p>Định dạng chi tiết (tên phần tử, vị trí chữ ký) do từng hệ thống tiếp nhận quy định: dùng <b>Tùy chỉnh nâng cao</b> để khớp, và nên thử nộp một file mẫu lên hệ thống thử nghiệm của nhà cung cấp hóa đơn / cơ quan thuế trước khi dùng chính thức.</p>
    <p>Kiểm tra chữ ký bằng dòng lệnh: <code>xmlsec1 --verify --id-attr:Id DLHDon hoadon_signed.xml</code></p>`],
  ["📎", "Ký file bất kỳ (Word, Excel, ZIP…)", `
    <p>Vào <b>Ký số → File bất kỳ</b>. Kết quả là file <code>.p7s</code> (chuẩn CMS/PKCS#7), gửi kèm file gốc. Người nhận kiểm tra bằng:</p>
    <pre>openssl cms -verify -binary -inform DER -in file.docx.p7s -content file.docx -noverify</pre>
    <p>Chọn <b>Nhúng nội dung gốc</b> nếu muốn một file duy nhất chứa cả dữ liệu và chữ ký.</p>`],
  ["🔍", "Kiểm tra chữ ký trên PDF", `
    <ul>
      <li><b>Adobe Acrobat Reader</b>: mở file → bảng <i>Signatures</i>. Lần đầu cần tin cậy chứng thư gốc của nhà cung cấp chữ ký số.</li>
      <li><b>Okular</b> (Linux): mở file → <i>Xem → Bảng chữ ký</i>.</li>
      <li><b>Dòng lệnh</b>: <code>pdfsig file_signed.pdf</code></li>
    </ul>`],
  ["📅", "Theo dõi và gia hạn chứng thư", `
    <ul>
      <li>Trang <b>Tổng quan</b> hiển thị số ngày còn lại; màu <span class="badge warn">vàng</span> khi còn ít hơn số ngày cảnh báo (mặc định 30, đổi trong Cài đặt), <span class="badge danger">đỏ</span> khi đã hết hạn.</li>
      <li>Ứng dụng gửi <b>thông báo hệ thống</b> khi phát hiện chứng thư sắp hết hạn.</li>
      <li>Bấm <b>Nhắc gia hạn</b> để tạo sự kiện lịch (.ics) có báo trước, rồi thêm vào Google Calendar/Outlook/Thunderbird.</li>
      <li>Để gia hạn: liên hệ nhà cung cấp ghi ở dòng <i>Nhà cung cấp</i> của chứng thư. Sau khi gia hạn, chứng thư mới được nạp vào token; bấm <b>Quét lại</b>.</li>
      <li>Kiểm tra tự động bằng dòng lệnh (dùng cho cron): <code>linuxsign expiry --days 30</code> trả mã lỗi 1 khi có chứng thư sắp hết hạn.</li>
    </ul>`],
  ["🖥️", "Chạy nền ở khay hệ thống", `
    <ul>
      <li>Đóng cửa sổ: LinuxSign thu nhỏ xuống <b>khay hệ thống</b> (góc màn hình), tiếp tục theo dõi token, hạn chứng thư và chạy agent cho web.</li>
      <li>Menu khay: mở cửa sổ, xem token đang cắm và tình trạng hạn, bật/tắt agent, khởi động cùng hệ thống, quét lại, thoát hẳn.</li>
      <li>Khi cửa sổ đang ẩn, ứng dụng báo khi cắm/rút token và nhắc hằng ngày nếu có chứng thư sắp hết hạn.</li>
      <li>Trên GNOME (Ubuntu), khay hệ thống cần tiện ích <i>AppIndicator</i> (Ubuntu đã có sẵn; bản GNOME khác: cài <code>gnome-shell-extension-appindicator</code>).</li>
      <li>Muốn đóng cửa sổ là thoát luôn: tắt trong Cài đặt → Chạy nền.</li>
    </ul>`],
  ["🔐", "Mã PIN và bảo mật", `
    <ul>
      <li>Token tự khóa sau một số lần nhập sai PIN liên tiếp (tùy loại token). Ứng dụng cảnh báo khi chỉ còn 1 lần.</li>
      <li>Khi đã bị khóa, phải liên hệ nhà cung cấp chữ ký số để mở khóa: ứng dụng không thể và không thử mở khóa.</li>
      <li>PIN chỉ được chuyển thẳng tới token cho từng lần ký, không được lưu lại.</li>
      <li>Khóa bí mật nằm trong chip của token và không bao giờ rời khỏi token.</li>
    </ul>`],
  ["🌐", "Tích hợp với ứng dụng web", `
    <p>Bật <b>Agent</b> trong Cài đặt và thêm địa chỉ website được phép. Website gọi tới <code>http://127.0.0.1:18080</code>:</p>
    <pre>// Lấy danh sách chứng thư
const { tokens } = await (await fetch("http://127.0.0.1:18080/certificates")).json();
const cert = tokens[0].certificates[0];

// Ký hóa đơn điện tử XML (profile: "einvoice" | "enveloped" | "xades")
const x = await fetch("http://127.0.0.1:18080/sign/xml", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ cert_id: cert.cert_id, pin, xml_b64, profile: "einvoice" }),
});

// Ký PDF
const r = await fetch("http://127.0.0.1:18080/sign/pdf", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ cert_id: cert.cert_id, pin, pdf_b64, reason: "Duyệt",
                         page: 1, rect: [350, 40, 560, 110] }),
});
const { pdf_b64: signed } = await r.json();

// Ký băm (cho XML/hóa đơn điện tử tự dựng ở phía ứng dụng)
await fetch("http://127.0.0.1:18080/sign", { method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ cert_id: cert.cert_id, pin, digest_b64, hash: "sha256" }) });</pre>
    <p>Mã lỗi: <code>401</code> sai/khóa PIN · <code>403</code> website chưa được phép · <code>404</code> không thấy chứng thư · <code>500</code> ký thất bại.</p>`],
  ["🛠️", "Xử lý sự cố", `
    <ul>
      <li><b>Không thấy token</b>: kiểm tra <code>pcscd</code> đang chạy, thử cổng USB khác, chạy <code>pcsc_scan</code> để xem hệ thống có nhận thẻ không.</li>
      <li><b>Thấy driver nhưng không có chứng thư</b>: driver hiện có không hỗ trợ chip của token; cài driver chính hãng của nhà cung cấp.</li>
      <li><b>Driver nằm ở vị trí lạ</b>: thêm đường dẫn file <code>.so</code>/<code>.dll</code> vào Cài đặt → Driver PKCS#11 bổ sung.</li>
      <li><b>Driver bị treo/crash</b>: LinuxSign chạy mỗi driver trong tiến trình riêng nên ứng dụng không bị ảnh hưởng; driver lỗi được báo ở trang Chẩn đoán và có thể đưa vào danh sách bỏ qua.</li>
      <li><b>Một token, nhiều driver</b>: ứng dụng dùng driver chính hãng trước, OpenSC làm dự phòng.</li>
    </ul>`],
];
$("#guide").innerHTML = GUIDE.map(([e, t, b], i) => `<details ${i === 0 ? "open" : ""}><summary><span>${e}</span>${t}</summary><div class="body">${b}</div></details>`).join("");

// ------------------------------------------------------------------ settings
const lines = (s) => s.split("\n").map((x) => x.trim()).filter(Boolean);
async function loadSettings() {
  const c = (state.config = await invoke("get_config"));
  $("#s-warn").value = c.expiry_warn_days;
  $("#s-reason").value = c.default_reason || "";
  $("#s-location").value = c.default_location || "";
  $("#s-tsa").value = c.tsa_url || "";
  $("#s-agent").checked = c.agent_enabled;
  $("#s-port").value = c.agent_port;
  $("#s-origins").value = c.agent_allowed_origins.join("\n");
  $("#s-modules").value = c.extra_modules.join("\n");
  $("#s-dirs").value = c.extra_search_dirs.join("\n");
  $("#s-exclude").value = c.exclude_modules.join("\n");
  $("#s-bg").checked = c.run_in_background;
  $("#s-font").value = c.signature_font || "";
  try { $("#s-autostart").checked = await invoke("get_autostart"); } catch (_) {}
  updateAgent(await invoke("agent_status"));
}
$("#btn-save").addEventListener("click", async () => {
  const c = {
    ...state.config,
    expiry_warn_days: Math.max(1, Number($("#s-warn").value) || 30),
    default_reason: $("#s-reason").value.trim() || null,
    default_location: $("#s-location").value.trim() || null,
    tsa_url: $("#s-tsa").value.trim() || null,
    agent_enabled: $("#s-agent").checked,
    agent_port: Number($("#s-port").value) || 18080,
    agent_allowed_origins: lines($("#s-origins").value),
    extra_modules: lines($("#s-modules").value),
    extra_search_dirs: lines($("#s-dirs").value),
    exclude_modules: lines($("#s-exclude").value),
    run_in_background: $("#s-bg").checked,
    signature_font: $("#s-font").value.trim() || null,
  };
  try {
    updateAgent(await invoke("save_config", { cfg: c }));
    state.config = c;
    toast("Đã lưu cài đặt");
    scan(true, true);
  } catch (e) { toast(String(e), "danger"); }
});
$("#s-autostart").addEventListener("change", async (e) => {
  try {
    await invoke("set_autostart", { enabled: e.target.checked });
    toast(e.target.checked ? "Sẽ tự khởi động (ẩn ở khay) khi đăng nhập" : "Đã tắt tự khởi động");
  } catch (err) { e.target.checked = !e.target.checked; syncSwitches(); toast(String(err), "danger"); }
});
$("#pick-font").addEventListener("click", async () => {
  const p = await invoke("pick_file", { kind: "font" });
  if (p) $("#s-font").value = p;
});

function syncSwitches() {
  $$(".switch").forEach((sw) => { $(".switch-text", sw).textContent = $("input", sw).checked ? "Bật" : "Tắt"; });
}
document.addEventListener("change", (e) => { if (e.target.classList.contains("toggle")) syncSwitches(); });

function updateAgent(a) {
  const pill = $("#agent-pill");
  pill.className = `pill ${a.running ? "on" : a.error ? "err" : ""}`;
  pill.textContent = a.running ? `Agent: :${a.port}` : a.error ? "Agent: lỗi" : "Agent: tắt";
  $("#agent-detail").innerHTML = a.running ? `Đang chạy tại <code>http://127.0.0.1:${a.port}</code>` : a.error ? `<span style="color:var(--danger)">${esc(a.error)}</span>` : "Cho phép website ký số qua http://127.0.0.1";
  syncSwitches();
}

// ------------------------------------------------------------------ start
hydrateIcons();
(async () => {
  try {
    state.config = await invoke("get_config");
    updateAgent(await invoke("agent_status"));
  } catch (_) {}
  await scan(true);
  // Sự kiện từ khay hệ thống / luồng giám sát nền
  const ev = window.__TAURI__.event;
  if (ev) {
    ev.listen("tokens-changed", () => scan(false, true));
    ev.listen("config-changed", async () => {
      state.config = await invoke("get_config");
      updateAgent(await invoke("agent_status"));
      if ($("#page-settings").classList.contains("active")) loadSettings();
    });
  }
  // Phát hiện cắm/rút token: thăm dò lại các driver đã biết mỗi 4 giây khi cửa sổ đang hiển thị.
  setInterval(() => { if (!document.hidden) scan(false, true); }, 4000);
})();
