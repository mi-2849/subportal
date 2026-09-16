"use strict";

/* =========================================================
 * SubHub · 主账号托管的子账号门户
 * 纯静态前端，全部数据直连 GitHub REST API。
 * 仓库名规则： sub-<用户名>--<仓库名>   （ASCII，GitHub 仓库名限制）
 * 界面标签    ： 子:<用户名>:
 * ========================================================= */

const CFG = {
  main: "mi-2849",            // 主账号
  prefix: "sub-",             // 仓库名前缀
  sep: "--",                  // 前缀与仓库名的分隔符
  indexRepo: "subaccounts",   // 索引仓库（私有）
  indexPath: "accounts.json", // 索引文件
  api: "https://api.github.com",
  apiVersion: "2022-11-28",
};

const S = {
  username: "",
  token: "",
  isAdmin: false,
  repos: [],
};

const $ = (id) => document.getElementById(id);
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const LS_KEY = "subhub.session";

/* ---------------- 基础工具 ---------------- */

async function api(path, { method = "GET", body, token } = {}) {
  const tk = token ?? S.token;
  const res = await fetch(CFG.api + path, {
    method,
    headers: {
      Authorization: "Bearer " + tk,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": CFG.apiVersion,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return null;
  const text = await res.text();
  let data = text;
  try { data = text ? JSON.parse(text) : null; } catch (_) { /* 保持纯文本 */ }
  if (!res.ok) {
    const err = new Error((data && data.message) || "HTTP " + res.status);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

function b64decode(s) {
  const bin = atob(String(s).replace(/\s+/g, ""));
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}

function b64encode(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin);
}

/** 令牌指纹：只留前 16 位十六进制，用于比对，不可反推 */
async function tokenFingerprint(token) {
  try {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
  } catch (_) {
    return ""; // 非安全上下文（如 file://）无法计算
  }
}

let toastTimer = null;
function toast(text, kind) {
  const el = $("toast");
  el.textContent = text;
  el.className = "toast" + (kind ? " toast--" + kind : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add("hidden"), 3600);
  el.classList.remove("hidden");
}

/* ---------------- 索引仓库 ---------------- */

async function readIndex() {
  try {
    const f = await api(`/repos/${CFG.main}/${CFG.indexRepo}/contents/${CFG.indexPath}`);
    return { data: JSON.parse(b64decode(f.content)), sha: f.sha, exists: true };
  } catch (e) {
    if (e.status === 404) return { data: null, sha: null, exists: false };
    throw e;
  }
}

async function writeIndex(data, sha, message) {
  const body = { message, content: b64encode(JSON.stringify(data, null, 2) + "\n") };
  if (sha) body.sha = sha;
  return api(`/repos/${CFG.main}/${CFG.indexRepo}/contents/${CFG.indexPath}`, { method: "PUT", body });
}

/** 索引仓库不存在时按需创建（私有，带初始 README） */
async function ensureIndexRepo() {
  try {
    await api(`/repos/${CFG.main}/${CFG.indexRepo}`);
    return false;
  } catch (e) {
    if (e.status !== 404) throw e;
  }
  await api("/user/repos", {
    method: "POST",
    body: {
      name: CFG.indexRepo,
      private: true,
      auto_init: true,
      description: "SubHub 子账号索引（私有，请勿公开）",
    },
  });
  return true;
}

const emptyIndex = () => ({
  version: 1,
  main_account: CFG.main,
  prefix: CFG.prefix,
  sep: CFG.sep,
  updated_at: new Date().toISOString(),
  accounts: [],
});

/* ---------------- 登录 / 登出 ---------------- */

function showApp() {
  $("loginView").classList.add("hidden");
  $("appView").classList.remove("hidden");
  $("userBadge").textContent = S.isAdmin ? `主账号 ${CFG.main}` : `子:${S.username}:`;
  $("userBadge").className = "badge " + (S.isAdmin ? "badge--admin" : "badge--tag");
  $("btnAdmin").classList.toggle("hidden", !S.isAdmin);
}

function showLogin() {
  $("appView").classList.add("hidden");
  $("loginView").classList.remove("hidden");
}

function loginMsg(text, kind) {
  const el = $("loginMsg");
  el.textContent = text || "";
  el.className = "msg" + (kind ? " msg--" + kind : "");
}

async function doLogin() {
  const username = $("inUser").value.trim().toLowerCase();
  const token = $("inToken").value.trim();
  if (!username || !token) return loginMsg("用户名和令牌都要填", "err");
  if (!/^[a-z0-9][a-z0-9-]{1,28}$/.test(username))
    return loginMsg("用户名只能用小写字母、数字和连字符，2~29 位", "err");

  const btn = $("btnLogin");
  btn.disabled = true;
  btn.textContent = "验证中...";
  loginMsg("");

  try {
    const me = await api("/user", { token });           // 1) 令牌是否有效
    const isMainToken = (me.login || "").toLowerCase() === CFG.main.toLowerCase();

    const idx = await readIndex();                       // 2) 读索引
    const accounts = (idx.data && idx.data.accounts) || [];
    const rec = accounts.find((a) => a.username === username);

    if (username === CFG.main) {
      if (!isMainToken) throw new Error("该用户名是主账号，但令牌不属于主账号");
      S.isAdmin = true;
    } else {
      if (!rec) throw new Error("该用户名尚未注册，请让主账号先登记");
      const fp = await tokenFingerprint(token);
      if (rec.token_fp && fp && rec.token_fp !== fp) {
        toast("提示：令牌与注册记录不一致，已按记录放行", "err");
      }
      S.isAdmin = false;
    }

    S.username = username;
    S.token = token;
    localStorage.setItem(LS_KEY, JSON.stringify({ username, token }));
    showApp();
    await loadRepos();
  } catch (e) {
    loginMsg(e.message || "登录失败", "err");
  } finally {
    btn.disabled = false;
    btn.textContent = "登录";
  }
}

function logout() {
  localStorage.removeItem(LS_KEY);
  S.username = ""; S.token = ""; S.isAdmin = false; S.repos = [];
  $("inToken").value = "";
  showLogin();
}

/* ---------------- 面板切换 ---------------- */

function panel(name) {
  ["panelRepos", "panelRepo", "panelCreate", "panelAdmin"].forEach((id) => $(id).classList.add("hidden"));
  $(name).classList.remove("hidden");
}

/* ---------------- 仓库列表 ---------------- */

const repoPrefix = (username) => CFG.prefix + username + CFG.sep;

async function loadRepos() {
  panel("panelRepos");
  $("panelRepos").innerHTML = `<p class="section-title">我的仓库</p><p class="section-sub">加载中...</p>`;
  try {
    const all = await api("/user/repos?per_page=100&sort=updated&affiliation=owner");
    const pre = repoPrefix(S.username);
    S.repos = all.filter((r) => r.name.toLowerCase().startsWith(pre));
    renderRepos();
  } catch (e) {
    $("panelRepos").innerHTML = `<p class="section-title">我的仓库</p><p class="msg msg--err">加载失败：${esc(e.message)}</p>`;
  }
}

function renderRepos() {
  const pre = repoPrefix(S.username);
  const head = `
    <p class="section-title">我的仓库</p>
    <p class="section-sub">
      归属标签 <span class="badge badge--tag">子:${esc(S.username)}:</span>
      · 实际仓库名规则 <code class="prefix-hint">${esc(pre)}&lt;仓库名&gt;</code>
      · 共 ${S.repos.length} 个
    </p>`;

  if (!S.repos.length) {
    $("panelRepos").innerHTML = head + `<div class="empty">还没有仓库，点右上角「新建仓库」开一个。</div>`;
    return;
  }

  const cards = S.repos
    .map((r) => {
      const short = r.name.slice(pre.length);
      return `
      <article class="repo-card">
        <div class="repo-card__head">
          <span class="badge badge--tag">子:${esc(S.username)}:</span>
          <span class="badge">${r.private ? "私有" : "公开"}</span>
        </div>
        <div class="repo-card__name" data-repo="${esc(r.name)}">${esc(short)}</div>
        <p class="repo-card__desc">${esc(r.description || "暂无描述")}</p>
        <div class="repo-card__meta">
          <span><span class="dot"></span>${esc(r.default_branch || "main")}</span>
          <span>更新 ${esc(String(r.updated_at || "").slice(0, 10))}</span>
          <span>${r.open_issues_count || 0} Issues</span>
        </div>
      </article>`;
    })
    .join("");

  $("panelRepos").innerHTML = head + `<div class="repo-grid">${cards}</div>`;
  $("panelRepos").querySelectorAll("[data-repo]").forEach((el) => {
    el.style.cursor = "pointer";
    el.addEventListener("click", () => openRepo(el.dataset.repo));
  });
}

/* ---------------- 仓库详情 ---------------- */

async function openRepo(fullName) {
  const pre = repoPrefix(S.username);
  const short = fullName.startsWith(pre) ? fullName.slice(pre.length) : fullName;
  panel("panelRepo");
  $("panelRepo").innerHTML = `
    <p class="section-title">${esc(short)}</p>
    <p class="section-sub"><span class="badge badge--tag">子:${esc(S.username)}:</span> 加载中...</p>`;
  try {
    const [repo, files] = await Promise.all([
      api(`/repos/${CFG.main}/${fullName}`),
      api(`/repos/${CFG.main}/${fullName}/contents`).catch(() => []),
    ]);
    let readme = "";
    try {
      const f = await api(`/repos/${CFG.main}/${fullName}/contents/README.md`);
      readme = b64decode(f.content);
    } catch (_) { readme = ""; }

    $("panelRepo").innerHTML = `
      <p class="section-title">${esc(short)}</p>
      <p class="section-sub">
        <span class="badge badge--tag">子:${esc(S.username)}:</span>
        <span class="badge">${repo.private ? "私有" : "公开"}</span>
        <span class="badge">${esc(repo.default_branch || "main")}</span>
        <span class="badge">${esc(repo.name)}</span>
      </p>
      <div class="card">
        <p class="repo-card__desc">${esc(repo.description || "暂无描述")}</p>
        <p class="repo-card__meta">
          <span>Star ${repo.stargazers_count}</span> ·
          <span>Fork ${repo.forks_count}</span> ·
          <span>Issue ${repo.open_issues_count}</span> ·
          <span>更新 ${esc(String(repo.updated_at || "").slice(0, 10))}</span>
        </p>
        <p class="hint"><a href="${esc(repo.html_url)}" target="_blank" rel="noopener">在 GitHub 上打开 →</a></p>
      </div>
      <div class="card">
        <p class="field-label" style="margin-top:0">根目录文件</p>
        ${Array.isArray(files) && files.length
          ? `<ul class="file-list">${files.map((f) => `<li>${f.type === "dir" ? "📁" : "📄"} ${esc(f.name)}</li>`).join("")}</ul>`
          : `<p class="hint">空仓库或无法读取目录。</p>`}
      </div>
      <div class="card">
        <p class="field-label" style="margin-top:0">README</p>
        ${readme ? `<pre class="readme">${esc(readme)}</pre>` : `<p class="hint">没有 README.md。</p>`}
      </div>
      <button class="btn" id="btnBack" type="button">← 返回列表</button>`;
    $("btnBack").addEventListener("click", loadRepos);
  } catch (e) {
    $("panelRepo").innerHTML = `<p class="section-title">${esc(short)}</p><p class="msg msg--err">加载失败：${esc(e.message)}</p>`;
  }
}

/* ---------------- 新建仓库 ---------------- */

function renderCreate() {
  panel("panelCreate");
  const pre = repoPrefix(S.username);
  $("panelCreate").innerHTML = `
    <p class="section-title">新建仓库</p>
    <p class="section-sub">实际仓库名会自动带上归属前缀</p>
    <div class="card">
      <label class="field-label" style="margin-top:0">仓库名</label>
      <div class="form-row">
        <span class="prefix-hint">${esc(pre)}</span>
        <div class="grow"><input id="newName" class="input input--mono" placeholder="demo" spellcheck="false" /></div>
      </div>
      <label class="field-label">描述（可选）</label>
      <input id="newDesc" class="input" placeholder="这个仓库是干嘛的" />
      <label class="field-label" style="display:flex;align-items:center;gap:8px">
        <input id="newPrivate" type="checkbox" checked /> 私有仓库
      </label>
      <div style="margin-top:16px;display:flex;gap:10px">
        <button class="btn btn--primary" id="btnCreate" type="button">创建</button>
        <button class="btn btn--ghost" id="btnCancel" type="button">取消</button>
      </div>
      <p id="createMsg" class="msg"></p>
    </div>`;
  $("btnCancel").addEventListener("click", loadRepos);
  $("btnCreate").addEventListener("click", doCreate);
}

async function doCreate() {
  const raw = $("newName").value.trim().toLowerCase();
  const short = raw.replace(/[^a-z0-9._-]/g, "-").replace(/^-+|-+$/g, "");
  const msg = $("createMsg");
  if (!short) { msg.textContent = "仓库名只能用小写字母、数字、. - _"; msg.className = "msg msg--err"; return; }
  if (raw !== short) { msg.textContent = "仓库名含非法字符，已自动改为 " + short; msg.className = "msg"; }

  const name = repoPrefix(S.username) + short;
  if (name.length > 100) { msg.textContent = "仓库名过长"; msg.className = "msg msg--err"; return; }

  const btn = $("btnCreate");
  btn.disabled = true; btn.textContent = "创建中...";
  try {
    await api("/user/repos", {
      method: "POST",
      body: {
        name,
        private: $("newPrivate").checked,
        auto_init: true,
        description: $("newDesc").value.trim() || `子:${S.username}: 创建`,
      },
    });
    toast("已创建 " + name, "ok");
    await loadRepos();
  } catch (e) {
    msg.textContent = "创建失败：" + e.message;
    msg.className = "msg msg--err";
  } finally {
    btn.disabled = false; btn.textContent = "创建";
  }
}

/* ---------------- 注册子账号（仅主账号） ---------------- */

async function renderAdmin() {
  panel("panelAdmin");
  $("panelAdmin").innerHTML = `
    <p class="section-title">注册子账号</p>
    <p class="section-sub">登记后该用户名才能登录本站；记录写入私有索引仓库 <code class="prefix-hint">${esc(CFG.main)}/${esc(CFG.indexRepo)}</code></p>
    <div class="card">
      <label class="field-label" style="margin-top:0">子账号用户名</label>
      <input id="admUser" class="input input--mono" placeholder="alice" spellcheck="false" />
      <label class="field-label">该子账号使用的令牌</label>
      <input id="admToken" class="input input--mono" type="password" placeholder="ghp_... / github_pat_..." />
      <p class="hint">
        按你的要求，令牌会写入私有索引仓库。注意两点：<br />
        1) 该仓库为私有，但任何能读到它的人都会拿到全部子账号令牌；<br />
        2) GitHub 的 secret scanning 对私有仓库默认不查，但一旦仓库转为公开或令牌外泄，仍可能被检测并吊销。
      </p>
      <div style="margin-top:16px">
        <button class="btn btn--primary" id="btnAdmSave" type="button">登记</button>
      </div>
      <p id="admMsg" class="msg"></p>
    </div>
    <div class="card">
      <p class="field-label" style="margin-top:0">已登记子账号</p>
      <div id="admList">加载中...</div>
    </div>`;
  $("btnAdmSave").addEventListener("click", doRegister);
  await refreshAdminList();
}

async function refreshAdminList() {
  const box = $("admList");
  try {
    const idx = await readIndex();
    const accounts = (idx.data && idx.data.accounts) || [];
    if (!accounts.length) { box.innerHTML = `<p class="hint">还没有登记任何子账号。</p>`; return; }
    box.innerHTML = `
      <table class="table">
        <thead><tr><th>用户名</th><th>标签</th><th>令牌指纹</th><th>仓库名前缀</th><th>登记时间</th></tr></thead>
        <tbody>
          ${accounts.map((a) => `
            <tr>
              <td><strong>${esc(a.username)}</strong></td>
              <td><span class="badge badge--tag">子:${esc(a.username)}:</span></td>
              <td><code>${esc(a.token_fp || "—")}</code></td>
              <td><code>${esc(repoPrefix(a.username))}</code></td>
              <td>${esc(String(a.created_at || "").slice(0, 10))}</td>
            </tr>`).join("")}
        </tbody>
      </table>`;
  } catch (e) {
    box.innerHTML = `<p class="msg msg--err">读取索引失败：${esc(e.message)}</p>`;
  }
}

async function doRegister() {
  const username = $("admUser").value.trim().toLowerCase();
  const token = $("admToken").value.trim();
  const msg = $("admMsg");
  if (!/^[a-z0-9][a-z0-9-]{1,28}$/.test(username)) {
    msg.textContent = "用户名只能用小写字母、数字和连字符，2~29 位";
    msg.className = "msg msg--err"; return;
  }
  if (!token) { msg.textContent = "令牌不能为空"; msg.className = "msg msg--err"; return; }
  if (username === CFG.main) { msg.textContent = "不能把主账号登记为子账号"; msg.className = "msg msg--err"; return; }

  const btn = $("btnAdmSave");
  btn.disabled = true; btn.textContent = "写入中...";
  try {
    const created = await ensureIndexRepo();
    if (created) toast("已创建私有索引仓库 " + CFG.indexRepo, "ok");

    const idx = await readIndex();
    const data = idx.data || emptyIndex();
    data.accounts = data.accounts || [];
    if (data.accounts.some((a) => a.username === username)) throw new Error("该用户名已登记");

    data.accounts.push({
      username,
      token,                                   // 按你的选择明文存放于私有仓库
      token_fp: await tokenFingerprint(token), // 供登录时比对
      created_at: new Date().toISOString(),
    });
    data.updated_at = new Date().toISOString();

    await writeIndex(data, idx.sha, `register sub-account: ${username}`);
    msg.textContent = `已登记 ${username}`;
    msg.className = "msg msg--ok";
    $("admToken").value = "";
    await refreshAdminList();
    toast("登记完成", "ok");
  } catch (e) {
    msg.textContent = "登记失败：" + e.message;
    msg.className = "msg msg--err";
  } finally {
    btn.disabled = false; btn.textContent = "登记";
  }
}

/* ---------------- 启动 ---------------- */

function boot() {
  $("btnLogin").addEventListener("click", doLogin);
  $("inToken").addEventListener("keydown", (e) => { if (e.key === "Enter") doLogin(); });
  $("btnLogout").addEventListener("click", logout);
  $("btnRepos").addEventListener("click", loadRepos);
  $("btnNew").addEventListener("click", renderCreate);
  $("btnAdmin").addEventListener("click", renderAdmin);

  const saved = localStorage.getItem(LS_KEY);
  if (saved) {
    try {
      const { username, token } = JSON.parse(saved);
      $("inUser").value = username;
      $("inToken").value = token;
      doLogin();
      return;
    } catch (_) { /* 忽略损坏的会话 */ }
  }
  showLogin();
}

document.addEventListener("DOMContentLoaded", boot);
