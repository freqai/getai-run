const state = {
  token: localStorage.getItem("getai_portal_token") || "",
  user: null,
  authMode: "login",
};

const apiOrigin = window.location.port === "4173"
  ? `${window.location.protocol}//${window.location.hostname}:8417`
  : window.location.origin;
const apiBase = `${apiOrigin}/v0/portal`;

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

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

function updateHeaderButtons() {
  $("[data-auth-open='login']").classList.toggle("hidden", Boolean(state.user));
  $("[data-auth-open='register']").classList.toggle("hidden", Boolean(state.user));
  $("#openConsole").classList.toggle("hidden", !state.user);
}

function setAuthMode(mode) {
  state.authMode = mode;
  const isRegister = mode === "register";
  const isResetPassword = mode === "reset-password";

  if (isResetPassword) {
    $("#authModeText").textContent = "Reset Password";
    $("#authTitle").textContent = "重置密码";
    $("#authSubmit").textContent = "重置密码";
    $("#switchAuthMode").textContent = "返回登录";
    $("#forgotPassword").classList.add("hidden");
    $("#nameField").classList.add("hidden");
    $("#codeField").classList.remove("hidden");
    $("#confirmPasswordField").classList.remove("hidden");
    $("#authCode").required = true;
    $("#authPassword").required = true;
    $("#authPassword").setAttribute("autocomplete", "new-password");
  } else if (isRegister) {
    $("#authModeText").textContent = "Register";
    $("#authTitle").textContent = "注册 getai.run";
    $("#authSubmit").textContent = "注册并进入控制台";
    $("#switchAuthMode").textContent = "已有账号？去登录";
    $("#forgotPassword").classList.add("hidden");
    $("#nameField").classList.remove("hidden");
    $("#codeField").classList.remove("hidden");
    $("#confirmPasswordField").classList.add("hidden");
    $("#authCode").required = true;
    $("#authPassword").required = true;
    $("#authPassword").setAttribute("autocomplete", "new-password");
  } else {
    $("#authModeText").textContent = "Login";
    $("#authTitle").textContent = "登录 getai.run";
    $("#authSubmit").textContent = "登录";
    $("#switchAuthMode").textContent = "没有账号？立即注册";
    $("#forgotPassword").classList.remove("hidden");
    $("#nameField").classList.add("hidden");
    $("#codeField").classList.add("hidden");
    $("#confirmPasswordField").classList.add("hidden");
    $("#authCode").required = false;
    $("#authPassword").required = true;
    $("#authPassword").setAttribute("autocomplete", "current-password");
  }

  $("#authCode").value = "";
  $("#authError").textContent = "";
}

function openAuth(mode) {
  setAuthMode(mode);
  $("#authDialog").showModal();
}

async function checkAuthState() {
  if (!state.token) {
    updateHeaderButtons();
    return;
  }
  try {
    const me = await request("/me");
    state.user = me.user;
    updateHeaderButtons();
  } catch (error) {
    setToken("");
    state.user = null;
    updateHeaderButtons();
  }
}

$$("[data-auth-open]").forEach((button) => button.addEventListener("click", () => openAuth(button.dataset.authOpen)));
$("#openConsole").addEventListener("click", () => {
  window.location.href = "/console.html";
});
$("#closeAuth").addEventListener("click", () => $("#authDialog").close());
$("#switchAuthMode").addEventListener("click", () => {
  if (state.authMode === "reset-password") {
    setAuthMode("login");
  } else if (state.authMode === "login") {
    setAuthMode("register");
  } else {
    setAuthMode("login");
  }
});
$("#forgotPassword").addEventListener("click", () => setAuthMode("reset-password"));

$("#authForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("#authError").textContent = "";

  const email = $("#authEmail").value;
  const password = $("#authPassword").value;

  if (state.authMode === "reset-password") {
    const confirmPassword = $("#authConfirmPassword").value;
    const code = $("#authCode").value;
    if (password !== confirmPassword) {
      $("#authError").textContent = "两次输入的密码不一致";
      return;
    }
    try {
      const data = await request("/reset-password", {
        method: "POST",
        body: JSON.stringify({ email, code, new_password: password }),
      });
      setToken(data.token);
      state.user = data.user;
      $("#authDialog").close();
      updateHeaderButtons();
    } catch (error) {
      $("#authError").textContent = error.message;
    }
    return;
  }

  const payload = { email, password };
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
    updateHeaderButtons();
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

setAuthMode("login");
checkAuthState();
