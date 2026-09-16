"use strict";

/* =========================================================
 * SubHub · 主账号托管的子账号门户  v2
 * 纯静态前端，全部数据直连 GitHub REST API。
 *
 * 仓库名规则： sub-<用户名>--<仓库名>   （ASCII，GitHub 仓库名限制）
 * 界面标签    ： 子:<用户名>:
 * 登录顺序    ： 令牌 → 密码 → 用户名（每次登录都要重新填）
 * 数据存储    ： 主账号私有仓库 subaccounts / accounts.json
 * ========================================================= */

const CFG = {
  main: "mi-2849",            // 主账号
  prefix: "sub-",             // 仓库名前缀
  sep: "--",                  // 前缀与仓库名的分隔符
  indexRepo: "subaccounts",   // 索引仓库（私有）
  indexPath: "accounts.json", // 索引文件
  api: "https://api.github.com",
  apiVersion: "2022-11-28",
  kdf: { algo: "PBKDF2-SHA256", iter: 150000, hash: "SHA-256", bits: 256 },
  minPassword: 6,
};

const S = {
  token: "",
  password: "",
  meLogin: "",
  username: "",
  isAdmin: false,
  pendingUser: "",
  repos: [],
};

const $ = (id) => document.getElementById(id);
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

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
  try { data = text ? JSON.parse(text) : null; } catch (_) { /* 纯文本 */ }
  if (!res.ok) {
    const err = new Error((data && data.message) || "HTTP " + res.status);
    err.status = res.status;
    throw err;
  }
  return data;
}

const bytesToB64 = (u8) => btoa(Array.from(u8, (c) => String.fromCharCode(c)).join(""));
const b64ToBytes = (s) => Uint8Array.from(atob(String(s).replace(/\s+/g, "")), (c) => c.charCodeAt(0));

function b64decode(s) {
  return new TextDecoder().decode(b64ToBytes(s));
}
function b64encode(str) {
  const bytes = new TextEncoder().encode(str);
  return bytesToB64(bytes);
}

async function tokenFingerprint(token) {
  try {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
  } catch (_) {
    return "";
  }
}

/* ---------------- 密码（PBKDF2-SHA256 + 随机盐） ---------------- */

function assertCrypto() {
  if (!crypto || !crypto.subtle) {
    throw new Error("当前环境不支持密码学接口，请通过 https 访问本站（GitHub Pages 默认就是 https）");
  }
}

async function pbkdf2(password, saltBytes, iter) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: iter, hash: CFG.kdf.hash },
    key,
    CFG.kdf.bits
  );
  return new Uint8Array(bits);
}

/** 生成密码记录：算法、迭代次数、盐、哈希（全部 base64） */
async function hashPassword(password) {
  assertCrypto();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, CFG.kdf.iter);
  return {
    algo: CFG.kdf.algo,
    iter: CFG.kdf.iter,
    salt: bytesToB64(salt),
    hash: bytesToB64(hash),
    updated_at: new Date().toISOString(),
  };
}

async function verifyPassword(password, rec) {
  if (!rec || !rec.hash || !rec.salt) return false;
  assertCrypto();
  const hash = await pbkdf2(password, b64ToBytes(rec.salt), rec.iter || CFG.kdf.iter);
  const a = bytesToB64(hash);
  const b = String(rec.hash);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/* ---------------- Toast ---------------- */

let toastTimer = null;
function toast(text, kind) {
  const el = $("toast");
  el.textContent = text;
  el.className = "toast" + (kind ? " toast--" + kind : "");
  el.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add("hidden"), 3600);
}

/* ---------------- 索引仓库 ---------------- */

async function readIndex() {
  try {
    const f = await api(`/repos/${CFG.main}/${CFG.indexRepo}/contents/${CFG.indexPath}`);
    const data = JSON.parse(b64decode(f.content));
    if (!Array.isArray(data.accounts)) data.accounts = [];
    return { data, sha: f.sha, exists: true };
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
      description: "SubHub 账号索引（私有，请勿公开）",
    },
  });
  return true;
}

const emptyIndex = () => ({
  version: 2,
  main_account: CFG.main,
  prefix: CFG.prefix,
  sep: CFG.sep,
  updated_at: new Date().toISOString(),
  accounts: [],
});

/* ---------------- 登录流程：令牌 → 密码 → 用户名 ---------------- */

function loginMsg(text, kind) {
  const el = $("loginMsg");
  el.textContent = text || "";
  el.className = "msg" + (kind ? " msg--" + kind : "");
}
function setPwMsg(text, kind) {
  const el = $("setPwMsg");
  el.textContent = text || "";
  el.className = "msg" + (kind ? " msg--" + kind : "");
}

function gotoStep(n) {
  [1, 2, 3].forEach((i) => {
    $("step" + i).classList.toggle("hidden", i !== n);
    $("stepDot" + i).classList.toggle("is-active", i === n);
    $("stepDot" + i).classList.toggle("is-done", i < n);
  });
  loginMsg("");
}

/** 第一步：校验令牌 */
async function step1() {
  const token = $("inToken").value.trim();
  if (!token) return loginMsg("请先填访问令牌", "err");
  const btn = $("btnStep1");
  btn.disabled = true; btn.textContent = "验证中...";
  try {
    const me = await api("/user", { token });
    S.token = token;
    S.meLogin = (me.login || "").toLowerCase();
    gotoStep(2);
    loginMsg(`令牌有效，身份 ${me.login}`, "ok");
  } catch (e) {
    loginMsg("令牌无效：" + e.message, "err");
  } finally {
    btn.disabled = false; btn.textContent = "下一步";
  }
}

/** 第二步：暂存密码 */
function step2() {
  const pw = $("inPass").value;
  if (!pw) return loginMsg("请先填密码", "err");
  S.password = pw;
  gotoStep(3);
}

/** 第三步：收用户名并统一校验 */
async function doLogin() {
  const username = $("inUser").value.trim().toLowerCase();
  if (!username) return loginMsg("请填用户名", "err");
  if (!/^[a-z0-9][a-z0-9-]{1,28}$/.test(username)) {
    return loginMsg("用户名只能用小写字母、数字和连字符，2~29 位", "err");
  }

  const btn = $("btnLogin");
  btn.disabled = true; btn.textContent = "进入中...";
  try {
    const idx = await readIndex();
    const accounts = (idx.data && idx.data.accounts) || [];
    const rec = accounts.find((a) => a.username === username);
    const isMainName = username === CFG.main.toLowerCase();

    if (isMainName) {
      if (S.meLogin !== CFG.main.toLowerCase()) throw new Error("用户名是主账号，但这枚令牌不属于主账号");
      if (!rec || !rec.password) return openSetPassword(username, true); // 首次 → 设密码
      if (!(await verifyPassword(S.password, rec.password))) throw new Error("密码不正确");
      S.isAdmin = true;
    } else {
      if (!rec) throw new Error("该用户名尚未注册，请让主账号先登记");
      if (!rec.password) return openSetPassword(username, false);       // 子账号首次 → 设密码
      if (!(await verifyPassword(S.password, rec.password))) throw new Error("密码不正确");
      S.isAdmin = false;
    }

    S.username = username;
    S.password = "";
    $("inPass").value = "";
    showApp();
    await loadRepos();
  } catch (e) {
    loginMsg(e.message || "登录失败", "err");
  } finally {
    btn.disabled = false; btn.textContent = "进入";
  }
}

/* ---------------- 首次设置密码 ---------------- */

function openSetPassword(username, isMain) {
  S.pendingUser = username;
  $("setPwSub").textContent = isMain
    ? `主账号 ${username} 还没有设置密码，先设一个，之后登录都要用它。`
    : `子账号 ${username} 还没有设置密码，设置后即可进入。`;
  $("setPw1").value = S.password || "";
  $("setPw2").value = "";
  setPwMsg("");
  $("loginView").classList.add("hidden");
  $("setPwView").classList.remove("hidden");
}

async function saveSetPassword() {
  const p1 = $("setPw1").value;
  const p2 = $("setPw2").value;
  if (p1.length < CFG.minPassword) return setPwMsg(`密码至少 ${CFG.minPassword} 位`, "err");
  if (p1 !== p2) return setPwMsg("两次输入不一致", "err");

  const btn = $("btnSetPw");
  btn.disabled = true; btn.textContent = "保存中...";
  try {
    const pwRec = await hashPassword(p1);
    const created = await ensureIndexRepo();
    if (created) toast("已创建私有索引仓库 " + CFG.indexRepo, "ok");

    const idx = await readIndex();
    const data = idx.data || emptyIndex();
    data.version = 2;
    const isMain = S.pendingUser === CFG.main.toLowerCase();
    let entry = data.accounts.find((a) => a.username === S.pendingUser);
    if (!entry) {
      entry = {
        username: S.pendingUser,
        role: isMain ? "main" : "sub",
        token: S.token,
        token_fp: await tokenFingerprint(S.token),
        created_at: new Date().toISOString(),
      };
      data.accounts.push(entry);
    }
    entry.password = pwRec;
    entry.updated_at = new Date().toISOString();
    data.updated_at = new Date().toISOString();
    await writeIndex(data, idx.sha, `set password for ${S.pendingUser}`);

    S.username = S.pendingUser;
    S.password = "";
    $("setPwView").classList.add("hidden");
    $("loginView").classList.remove("hidden");
    $("inPass").value = "";
    showApp();
    await loadRepos();
    toast("密码已设置", "ok");
  } catch (e) {
    setPwMsg("保存失败：" + (e.message || e), "err");
  } finally {
    btn.disabled = false; btn.textContent = "保存并进入";
  }
}

/* ---------------- 视图切换 ---------------- */

function showApp() {
  $("setPwView").classList.add("hidden");
  $("loginView").classList.add("hidden");
  $("appView").classList.remove("hidden");
  $("userBadge").textContent = S.isAdmin ? `主账号 ${CFG.main}` : `子:${S.username}:`;
  $("userBadge").className = "badge " + (S.isAdmin ? "badge--admin" : "badge--tag");
  $("btnAdmin").classList.toggle("hidden", !S.isAdmin);
}

function showLogin() {
  $("appView").classList.add("hidden");
  $("setPwView").classList.add("hidden");
  $("loginView").classList.remove("hidden");
}

function logout() {
  S.token = ""; S.password = ""; S.meLogin = ""; S.username = ""; S.isAdmin = false; S.repos = [];
  $("inToken").value = ""; $("inPass").value = ""; $("inUser").value = "";
  gotoStep(1);
  showLogin();
}

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

  $("panelRepos").innerHTML =
    head +
    `<div class="repo-grid">` +
    S.repos
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
      .join("") +
    `</div>`;

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

/* ---------------- 注册子账号 / 重置密码（仅主账号） ---------------- */

async function renderAdmin() {
  panel("panelAdmin");
  $("panelAdmin").innerHTML = `
    <p class="section-title">注册子账号</p>
    <p class="section-sub">记录写入私有索引仓库 <code class="prefix-hint">${esc(CFG.main)}/${esc(CFG.indexRepo)}</code></p>
    <div class="card">
      <label class="field-label" style="margin-top:0">子账号用户名</label>
      <input id="admUser" class="input input--mono" placeholder="alice" spellcheck="false" />
      <label class="field-label">该子账号使用的令牌</label>
      <input id="admToken" class="input input--mono" type="password" placeholder="ghp_... / github_pat_..." />
      <label class="field-label">初始密码（留空则由子账号首次登录时自行设置）</label>
      <input id="admPass" class="input" type="password" placeholder="至少 ${CFG.minPassword} 位" />
      <p class="hint">
        令牌会写入私有索引仓库；密码只存 PBKDF2 哈希。<br />
        任何能读到该仓库的人都拿得到全部子账号令牌，请勿把仓库改为公开。
      </p>
      <div style="margin-top:16px">
        <button class="btn btn--primary" id="btnAdmSave" type="button">登记</button>
      </div>
      <p id="admMsg" class="msg"></p>
    </div>

    <div class="card">
      <p class="field-label" style="margin-top:0">重置子账号密码</p>
      <div class="form-row">
        <div class="grow"><input id="rstUser" class="input input--mono" placeholder="用户名" spellcheck="false" /></div>
        <div class="grow"><input id="rstPass" class="input" type="password" placeholder="新密码（至少 ${CFG.minPassword} 位）" /></div>
        <button class="btn" id="btnReset" type="button">重置</button>
      </div>
      <p id="rstMsg" class="msg"></p>
    </div>

    <div class="card">
      <p class="field-label" style="margin-top:0">已登记账号</p>
      <div id="admList">加载中...</div>
    </div>`;

  $("btnAdmSave").addEventListener("click", doRegister);
  $("btnReset").addEventListener("click", doResetPassword);
  await refreshAdminList();
}

async function refreshAdminList() {
  const box = $("admList");
  try {
    const idx = await readIndex();
    const accounts = (idx.data && idx.data.accounts) || [];
    if (!accounts.length) { box.innerHTML = `<p class="hint">还没有登记任何账号。</p>`; return; }
    box.innerHTML = `
      <table class="table">
        <thead><tr><th>用户名</th><th>角色</th><th>标签</th><th>密码</th><th>仓库前缀</th><th>更新时间</th></tr></thead>
        <tbody>
          ${accounts.map((a) => `
            <tr>
              <td><strong>${esc(a.username)}</strong></td>
              <td>${a.role === "main" ? "主账号" : "子账号"}</td>
              <td><span class="badge badge--tag">子:${esc(a.username)}:</span></td>
              <td>${a.password ? "已设置" : "<span style='color:var(--orange)'>未设置</span>"}</td>
              <td><code>${esc(repoPrefix(a.username))}</code></td>
              <td>${esc(String(a.updated_at || a.created_at || "").slice(0, 10))}</td>
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
  const pass = $("admPass").value;
  const msg = $("admMsg");

  if (!/^[a-z0-9][a-z0-9-]{1,28}$/.test(username)) {
    msg.textContent = "用户名只能用小写字母、数字和连字符，2~29 位";
    msg.className = "msg msg--err"; return;
  }
  if (!token) { msg.textContent = "令牌不能为空"; msg.className = "msg msg--err"; return; }
  if (username === CFG.main) { msg.textContent = "不能把主账号登记为子账号"; msg.className = "msg msg--err"; return; }
  if (pass && pass.length < CFG.minPassword) {
    msg.textContent = `密码至少 ${CFG.minPassword} 位`; msg.className = "msg msg--err"; return;
  }

  const btn = $("btnAdmSave");
  btn.disabled = true; btn.textContent = "写入中...";
  try {
    const created = await ensureIndexRepo();
    if (created) toast("已创建私有索引仓库 " + CFG.indexRepo, "ok");

    const idx = await readIndex();
    const data = idx.data || emptyIndex();
    data.version = 2;
    if (data.accounts.some((a) => a.username === username)) throw new Error("该用户名已登记");

    data.accounts.push({
      username,
      role: "sub",
      token,                                    // 按既定选择明文存放于私有仓库
      token_fp: await tokenFingerprint(token),
      password: pass ? await hashPassword(pass) : null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
    data.updated_at = new Date().toISOString();

    await writeIndex(data, idx.sha, `register sub-account: ${username}`);
    msg.textContent = `已登记 ${username}` + (pass ? "（含初始密码）" : "（未设密码，首次登录时自设）");
    msg.className = "msg msg--ok";
    $("admToken").value = ""; $("admPass").value = "";
    await refreshAdminList();
    toast("登记完成", "ok");
  } catch (e) {
    msg.textContent = "登记失败：" + e.message;
    msg.className = "msg msg--err";
  } finally {
    btn.disabled = false; btn.textContent = "登记";
  }
}

async function doResetPassword() {
  const username = $("rstUser").value.trim().toLowerCase();
  const pass = $("rstPass").value;
  const msg = $("rstMsg");
  if (!username) { msg.textContent = "请填用户名"; msg.className = "msg msg--err"; return; }
  if (pass.length < CFG.minPassword) { msg.textContent = `密码至少 ${CFG.minPassword} 位`; msg.className = "msg msg--err"; return; }

  const btn = $("btnReset");
  btn.disabled = true; btn.textContent = "写入中...";
  try {
    const idx = await readIndex();
    if (!idx.exists) throw new Error("索引仓库还不存在");
    const data = idx.data;
    const entry = data.accounts.find((a) => a.username === username);
    if (!entry) throw new Error("没有这个用户名");

    entry.password = await hashPassword(pass);
    entry.updated_at = new Date().toISOString();
    data.updated_at = new Date().toISOString();
    await writeIndex(data, idx.sha, `reset password for ${username}`);

    msg.textContent = `已重置 ${username} 的密码`;
    msg.className = "msg msg--ok";
    $("rstPass").value = "";
    await refreshAdminList();
    toast("密码已重置", "ok");
  } catch (e) {
    msg.textContent = "重置失败：" + e.message;
    msg.className = "msg msg--err";
  } finally {
    btn.disabled = false; btn.textContent = "重置";
  }
}

/* ---------------- 启动 ---------------- */

function boot() {
  $("btnStep1").addEventListener("click", step1);
  $("btnStep2").addEventListener("click", step2);
  $("btnLogin").addEventListener("click", doLogin);
  $("btnBack2").addEventListener("click", () => gotoStep(1));
  $("btnBack3").addEventListener("click", () => gotoStep(2));
  $("btnSetPw").addEventListener("click", saveSetPassword);
  $("inUser").addEventListener("keydown", (e) => { if (e.key === "Enter") doLogin(); });
  $("btnLogout").addEventListener("click", logout);
  $("btnRepos").addEventListener("click", loadRepos);
  $("btnNew").addEventListener("click", renderCreate);
  $("btnAdmin").addEventListener("click", renderAdmin);

  gotoStep(1);
  showLogin();
}

document.addEventListener("DOMContentLoaded", boot);
