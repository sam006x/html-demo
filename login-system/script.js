function $(id) { return document.getElementById(id); }

function setError(inputId, msgId, msg) {
  const el = $(inputId);
  const hint = $(msgId);
  if (!el) return;
  el.classList.add("error");
  el.classList.remove("ok");
  if (hint) hint.textContent = msg;
}

function clearError(inputId, msgId) {
  const el = $(inputId);
  const hint = $(msgId);
  if (!el) return;
  el.classList.remove("error");
  el.classList.add("ok");
  if (hint) hint.textContent = "";
}

// ── Login form ──────────────────────────────────────────────────
const loginForm = $("loginForm");
if (loginForm) {
  loginForm.addEventListener("submit", function (e) {
    let valid = true;
    const username = $("username").value.trim();
    const password = $("password").value;

    if (!username) {
      setError("username", "usernameErr", "Username is required.");
      valid = false;
    } else { clearError("username", "usernameErr"); }

    if (!password) {
      setError("password", "passwordErr", "Password is required.");
      valid = false;
    } else { clearError("password", "passwordErr"); }

    if (!valid) e.preventDefault();
    else $("submitBtn").disabled = true;
  });
}

// ── Register form ───────────────────────────────────────────────
const registerForm = $("registerForm");
if (registerForm) {
  const usernameInput = $("reg_username");
  const passwordInput = $("reg_password");
  const confirmInput  = $("reg_confirm");
  const strengthFill  = $("strengthFill");
  const strengthLabel = $("strengthLabel");

  // Live password strength
  if (passwordInput) {
    passwordInput.addEventListener("input", function () {
      const val = this.value;
      let score = 0;
      if (val.length >= 8)          score++;
      if (/[A-Z]/.test(val))        score++;
      if (/[0-9]/.test(val))        score++;
      if (/[^A-Za-z0-9]/.test(val)) score++;

      const colors = ["", "#f85149", "#d29922", "#3fb950", "#3fb950"];
      const labels = ["", "Weak", "Fair", "Strong", "Very strong"];
      if (strengthFill) {
        strengthFill.style.width   = (score * 25) + "%";
        strengthFill.style.background = colors[score] || "#30363d";
      }
      if (strengthLabel) strengthLabel.textContent = val ? labels[score] : "";
    });
  }

  // Live username check: 3-20 chars, alphanumeric + underscore
  if (usernameInput) {
    usernameInput.addEventListener("blur", function () {
      const val = this.value.trim();
      if (!val) {
        setError("reg_username", "regUsernameErr", "Username is required.");
      } else if (!/^[a-zA-Z0-9_]{3,20}$/.test(val)) {
        setError("reg_username", "regUsernameErr",
          "3–20 characters, letters, numbers and underscore only.");
      } else {
        clearError("reg_username", "regUsernameErr");
      }
    });
  }

  registerForm.addEventListener("submit", function (e) {
    let valid = true;

    const uVal = usernameInput ? usernameInput.value.trim() : "";
    const pVal = passwordInput ? passwordInput.value : "";
    const cVal = confirmInput  ? confirmInput.value  : "";

    if (!uVal || !/^[a-zA-Z0-9_]{3,20}$/.test(uVal)) {
      setError("reg_username", "regUsernameErr", "Enter a valid username (3–20 chars).");
      valid = false;
    } else { clearError("reg_username", "regUsernameErr"); }

    if (pVal.length < 8) {
      setError("reg_password", "regPasswordErr", "Password must be at least 8 characters.");
      valid = false;
    } else { clearError("reg_password", "regPasswordErr"); }

    if (cVal !== pVal) {
      setError("reg_confirm", "regConfirmErr", "Passwords do not match.");
      valid = false;
    } else { clearError("reg_confirm", "regConfirmErr"); }

    if (!valid) e.preventDefault();
    else $("regSubmitBtn").disabled = true;
  });
}

// ── Forgot password form ────────────────────────────────────────
const forgotForm = $("forgotForm");
if (forgotForm) {
  forgotForm.addEventListener("submit", function (e) {
    const email = $("email").value.trim();
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !re.test(email)) {
      setError("email", "emailErr", "Enter a valid email address.");
      e.preventDefault();
    } else {
      clearError("email", "emailErr");
      $("forgotBtn").disabled = true;
    }
  });
}

// ── Reset password form ─────────────────────────────────────────
const resetForm = $("resetForm");
if (resetForm) {
  resetForm.addEventListener("submit", function (e) {
    const pVal = $("new_password").value;
    const cVal = $("confirm_password").value;
    let valid  = true;

    if (pVal.length < 8) {
      setError("new_password", "newPassErr", "Minimum 8 characters.");
      valid = false;
    } else { clearError("new_password", "newPassErr"); }

    if (cVal !== pVal) {
      setError("confirm_password", "confirmPassErr", "Passwords do not match.");
      valid = false;
    } else { clearError("confirm_password", "confirmPassErr"); }

    if (!valid) e.preventDefault();
  });
}
