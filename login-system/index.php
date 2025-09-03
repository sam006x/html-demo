<?php
session_start();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureAuth – Login</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <div class="card">

    <div class="brand">
      <div class="brand-icon">🔐</div>
      <div class="brand-name">Secure<span>Auth</span></div>
    </div>

    <h2>Sign in</h2>
    <p class="subtitle">Enter your credentials to access your account.</p>

    <?php if (isset($_SESSION['message'])): ?>
      <div class="alert alert-<?php echo $_SESSION['message_type'] ?? 'danger'; ?>">
        <span class="alert-icon">
          <?php echo ($_SESSION['message_type'] ?? '') === 'success' ? '✓' : '⚠'; ?>
        </span>
        <?php echo htmlspecialchars($_SESSION['message']);
              unset($_SESSION['message']);
              unset($_SESSION['message_type']); ?>
      </div>
    <?php endif; ?>

    <div class="lockout-bar" id="lockoutBar"></div>

    <form id="loginForm" action="login.php" method="POST" novalidate>
      <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username"
               autocomplete="username" autocapitalize="none" required>
        <p class="field-hint err" id="usernameErr"></p>
      </div>

      <div class="form-group">
        <label for="password">
          Password
          <a href="forgot_password.php" class="forgot-link">Forgot password?</a>
        </label>
        <input type="password" id="password" name="password"
               autocomplete="current-password" required>
        <p class="field-hint err" id="passwordErr"></p>
      </div>

      <button type="submit" class="btn btn-primary" id="submitBtn">Sign in</button>
    </form>

    <div class="card-footer">
      Don't have an account? <a href="register.php">Create one</a>
    </div>
  </div>

  <script src="script.js"></script>
</body>
</html>