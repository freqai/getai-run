const state = {
  token: localStorage.getItem("getai_portal_token") || "",
  user: null,
  apiKeys: [],
  orders: [],
  plans: [],
  authMode: "login",
};

const apiOrigin = window.location.port === "4173"
  ? `${window.location.protocol}//${window.location.hostname}:8417`
  : window.location.origin;
const apiBase = `${apiOrigin}/v0/portal`;

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

function money(cents) {
  return `$${(Number(cents || 0) / 100).toFixed(2)}`;
}

function dateText(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}

async function request(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const response = await fetch(`${apiBase}${path}`, { ...options, headers });
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `请求失败：${response.status}`);
  return data;
}

function setToken(token) {
  state.token = token || "";
  if (state.token) {
    localStorage.setItem("getai_portal_token", state.token);
  } else {
    localStorage.removeItem("getai_portal_token");
  }
}

function showMarketing() {
  $("#marketingPage").classList.remove("hidden");
  $("#consoleApp").classList.add("hidden");
  $("[data-auth-open='login']").classList.toggle("hidden", Boolean(state.user));
  $("[data-auth-open='register']").classList.toggle("hidden", Boolean(state.user));
  $("#openConsole").classList.toggle("hidden", !state.user);
}

function showConsole() {
  $("#marketingPage").classList.add("hidden");
  $("#consoleApp").classList.remove("hidden");
  $("[data-auth-open='login']").classList.add("hidden");
  $("[data-auth-open='register']").classList.add("hidden");
  $("#openConsole").classList.remove("hidden");
  renderAll();
}

function setAuthMode(mode) {
  state.authMode = mode;
  const isRegister = mode === "register";
  $("#authModeText").textContent = isRegister ? "Register" : "Login";
  $("#authTitle").textContent = isRegister ? "注册 getai.run" : "登录 getai.run";
  $("#authSubmit").textContent = isRegister ? "注册并进入控制台" : "登录";
  $("#switchAuthMode").textContent = isRegister ? "已有账号？去登录" : "没有账号？立即注册";
  $("#nameField").classList.toggle("hidden", !isRegister);
  $("#codeField").classList.toggle("hidden", !isRegister);
  $("#authCode").required = isRegister;
  $("#authCode").value = "";
  $("#authError").textContent = "";
}

function openAuth(mode) {
  setAuthMode(mode);
  $("#authDialog").showModal();
}

function currentPanelName(tab) {
  const map = { overview: "仪表盘", keys: "API 密钥", billing: "充值下单", orders: "我的订单", docs: "文档" };
  return map[tab] || "仪表盘";
}

function switchTab(tab) {
  $$(".console-nav button").forEach((button) => button.classList.toggle("active", button.dataset.consoleTab === tab));
  $$(".console-panel").forEach((panel) => panel.classList.remove("active"));
  $(`#panel-${tab}`).classList.add("active");
  $("#consoleTitle").textContent = currentPanelName(tab);
}

function renderUser() {
  const user = state.user;
  if (!user) return;
  $("#balancePill").textContent = money(user.balance_cents);
  $("#overviewBalance").textContent = money(user.balance_cents);
  $("#userPill").textContent = user.name || user.email || "User";
}

function renderOverview() {
  $("#overviewKeyCount").textContent = String(state.apiKeys.length);
  $("#overviewOrderCount").textContent = String(state.orders.length);
}

function renderKeys() {
  const table = $("#keysTable");
  if (!state.apiKeys.length) {
    table.innerHTML = '<div class="table-row"><strong>暂无 API 密钥</strong><small>创建一个密钥后即可调用接口。</small><span></span><span></span><span></span></div>';
    renderOverview();
    return;
  }
  table.innerHTML = `
    <div class="table-head">
      <span>名称</span><span>API 密钥</span><span>分组</span><span>状态</span><span>操作</span>
    </div>
    ${state.apiKeys.map((key) => `
      <div class="table-row">
        <strong>${escapeHTML(key.name)}</strong>
        <span class="key-prefix">${escapeHTML(key.key_prefix)}...</span>
        <span>${escapeHTML(key.group || "默认号池")}</span>
        <span class="status-pill">${key.disabled ? "禁用" : "活跃"}</span>
        <div class="row-actions">
          <button class="button button-secondary compact" type="button" data-disable-key="${key.id}">${key.disabled ? "启用" : "禁用"}</button>
          <button class="button button-secondary compact" type="button" data-delete-key="${key.id}">删除</button>
        </div>
      </div>
    `).join("")}
  `;
  renderOverview();
}

function renderPlans() {
  $("#planGrid").innerHTML = state.plans.map((plan) => `
    <article class="plan-card">
      <h3>${escapeHTML(plan.name)}</h3>
      <strong>${money(plan.amount_cents)}</strong>
      <p>到账额度 ${money(plan.credit_cents)}</p>
      <button class="button button-primary" type="button" data-create-order="${plan.id}">创建订单</button>
    </article>
  `).join("");
}

function renderOrders() {
  const table = $("#ordersTable");
  table.classList.add("orders-table");
  if (!state.orders.length) {
    table.innerHTML = '<div class="table-row"><strong>暂无订单</strong><small>选择充值套餐后会生成订单。</small><span></span><span></span><span></span></div>';
    renderOverview();
    return;
  }
  table.innerHTML = `
    <div class="table-head">
      <span>订单号</span><span>套餐</span><span>金额</span><span>状态</span><span>操作</span>
    </div>
    ${state.orders.map((order) => `
      <div class="table-row">
        <strong>${escapeHTML(order.id)}</strong>
        <span>${escapeHTML(order.plan_id)}</span>
        <span>${money(order.amount_cents)}<small> · ${dateText(order.created_at)}</small></span>
        <span class="status-pill">${order.status === "paid" ? "已支付" : "待支付"}</span>
        <div class="row-actions">
          ${order.status === "paid" ? "" : `<button class="button button-primary compact" type="button" data-pay-order="${order.id}">模拟支付</button>`}
        </div>
      </div>
    `).join("")}
  `;
  renderOverview();
}

function renderAll() {
  renderUser();
  renderKeys();
  renderPlans();
  renderOrders();
}

async function refreshPortal() {
  if (!state.token) {
    showMarketing();
    return;
  }
  try {
    const [me, keys, plans, orders] = await Promise.all([
      request("/me"),
      request("/api-keys"),
      request("/plans"),
      request("/orders"),
    ]);
    state.user = me.user;
    state.apiKeys = keys.api_keys || [];
    state.plans = plans.plans || [];
    state.orders = orders.orders || [];
    showConsole();
  } catch (error) {
    setToken("");
    state.user = null;
    showMarketing();
  }
}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[char]));
}

$$("[data-auth-open]").forEach((button) => button.addEventListener("click", () => openAuth(button.dataset.authOpen)));
$("#openConsole").addEventListener("click", () => showConsole());
$("#closeAuth").addEventListener("click", () => $("#authDialog").close());
$("#switchAuthMode").addEventListener("click", () => setAuthMode(state.authMode === "login" ? "register" : "login"));

$("#authForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("#authError").textContent = "";
  const payload = {
    email: $("#authEmail").value,
    password: $("#authPassword").value,
  };
  if (state.authMode === "register") {
    payload.name = $("#authName").value;
    payload.code = $("#authCode").value;
  }
  try {
    const data = await request(state.authMode === "register" ? "/register" : "/login", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    setToken(data.token);
    state.user = data.user;
    $("#authDialog").close();
    await refreshPortal();
  } catch (error) {
    $("#authError").textContent = error.message;
  }
});

$("#sendAuthCode").addEventListener("click", async () => {
  $("#authError").textContent = "";
  const button = $("#sendAuthCode");
  const email = $("#authEmail").value.trim();
  if (!email) {
    $("#authError").textContent = "请先填写邮箱";
    return;
  }
  button.disabled = true;
  const originalText = button.textContent;
  try {
    const data = await request("/auth-code", {
      method: "POST",
      body: JSON.stringify({ email, purpose: state.authMode }),
    });
    $("#authError").textContent = data.code ? `开发模式验证码：${data.code}` : "验证码已发送，请查看邮箱";
    button.textContent = "已发送";
  } catch (error) {
    $("#authError").textContent = error.message;
    button.disabled = false;
    button.textContent = originalText;
    return;
  }
  window.setTimeout(() => {
    button.disabled = false;
    button.textContent = originalText;
  }, 60000);
});

$("#logoutButton").addEventListener("click", async () => {
  try {
    await request("/logout", { method: "POST" });
  } catch (error) {
    // Session may already be invalid; local cleanup is enough for the browser.
  }
  setToken("");
  state.user = null;
  showMarketing();
});

$$("[data-console-tab]").forEach((button) => {
  button.addEventListener("click", () => {
    showConsole();
    switchTab(button.dataset.consoleTab);
  });
});

$("#createKeyButton").addEventListener("click", () => {
  $("#keyError").textContent = "";
  $("#newKeyBox").classList.add("hidden");
  $("#keyDialog").showModal();
});
$("#closeKeyDialog").addEventListener("click", () => $("#keyDialog").close());

$("#keyForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("#keyError").textContent = "";
  try {
    const data = await request("/api-keys", {
      method: "POST",
      body: JSON.stringify({ name: $("#keyName").value, group: $("#keyGroup").value }),
    });
    $("#newKeyValue").textContent = data.key;
    $("#newKeyBox").classList.remove("hidden");
    await refreshPortal();
  } catch (error) {
    $("#keyError").textContent = error.message;
  }
});

$("#copyNewKey").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("#newKeyValue").textContent);
  $("#copyNewKey").textContent = "已复制";
  window.setTimeout(() => { $("#copyNewKey").textContent = "复制"; }, 1200);
});

$("#refreshKeys").addEventListener("click", refreshPortal);
$("#refreshOrders").addEventListener("click", refreshPortal);

document.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const deleteKeyID = target.dataset.deleteKey;
  if (deleteKeyID) {
    await request(`/api-keys/${deleteKeyID}`, { method: "DELETE" });
    await refreshPortal();
    return;
  }
  const disableKeyID = target.dataset.disableKey;
  if (disableKeyID) {
    const key = state.apiKeys.find((item) => item.id === disableKeyID);
    await request(`/api-keys/${disableKeyID}`, {
      method: "PATCH",
      body: JSON.stringify({ disabled: !key?.disabled }),
    });
    await refreshPortal();
    return;
  }
  const planID = target.dataset.createOrder;
  if (planID) {
    const data = await request("/orders", { method: "POST", body: JSON.stringify({ plan_id: planID }) });
    state.orders.unshift(data.order);
    renderOrders();
    switchTab("orders");
    return;
  }
  const orderID = target.dataset.payOrder;
  if (orderID) {
    const data = await request(`/orders/${orderID}/mock-pay`, { method: "POST" });
    state.user = data.user;
    await refreshPortal();
  }
});

setAuthMode("login");
refreshPortal();
