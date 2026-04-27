const state = {
  token: localStorage.getItem("getai_portal_token") || "",
  user: null,
  apiKeys: [],
  orders: [],
  plans: [],
  usageLogs: [],
  usageNotice: "",
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

function redirectToLogin() {
  window.location.href = "/";
}

function currentPanelName(tab) {
  const map = { overview: "仪表盘", usage: "使用记录", keys: "API 密钥", billing: "充值下单", orders: "我的订单", docs: "文档" };
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

function renderUsage() {
  const table = $("#usageTable");
  if (!table) return;
  table.classList.add("usage-table");

  let noticeHTML = "";
  if (state.usageNotice) {
    noticeHTML = `<div class="console-notice">${escapeHTML(state.usageNotice)}</div>`;
  }

  if (!state.usageLogs || !state.usageLogs.length) {
    table.innerHTML = `${noticeHTML}<div class="table-row"><strong>暂无使用记录</strong><small>使用 PostgreSQL 后端时才会记录 API 调用历史。</small><span></span><span></span><span></span></div>`;
    return;
  }
  table.innerHTML = `
    ${noticeHTML}
    <div class="table-head">
      <span>时间</span><span>模型</span><span>提供商</span><span>Token</span><span>状态</span>
    </div>
    ${state.usageLogs.map((log) => `
      <div class="table-row">
        <strong>${dateText(log.requested_at)}</strong>
        <span>${escapeHTML(log.model)}</span>
        <span>${escapeHTML(log.provider)}</span>
        <span>入 ${log.input_tokens} | 出 ${log.output_tokens} | 总 ${log.total_tokens}</span>
        <span class="status-pill">${log.failed ? "失败" : "成功"}</span>
      </div>
    `).join("")}
  `;
}

async function refreshUsage() {
  try {
    const data = await request("/usage-logs");
    state.usageLogs = data.usage_logs || [];
    state.usageNotice = data.notice || "";
    renderUsage();
  } catch (error) {
    const table = $("#usageTable");
    if (table) {
      table.innerHTML = `<div class="table-row"><strong>加载失败</strong><small>${escapeHTML(error.message)}</small><span></span><span></span><span></span></div>`;
    }
  }
}

function renderAll() {
  renderUser();
  renderKeys();
  renderPlans();
  renderOrders();
  renderUsage();
}

async function refreshPortal() {
  if (!state.token) {
    redirectToLogin();
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
    renderAll();
    refreshUsage();
  } catch (error) {
    setToken("");
    state.user = null;
    redirectToLogin();
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

$$("[data-console-tab]").forEach((button) => {
  button.addEventListener("click", () => {
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

const refreshUsageElement = $("#refreshUsage");
if (refreshUsageElement) {
  refreshUsageElement.addEventListener("click", refreshUsage);
}

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

$("#logoutButton").addEventListener("click", async () => {
  try {
    await request("/logout", { method: "POST" });
  } catch (error) {
    // Session may already be invalid; local cleanup is enough for the browser.
  }
  setToken("");
  state.user = null;
  redirectToLogin();
});

refreshPortal();
