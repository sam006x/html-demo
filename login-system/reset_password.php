<?php

session_start();
require_once 'db.php';
require_once 'audit.php';

$token  = trim($_GET['token'] ?? $_POST['token'] ?? '');
$errors = [];
$done   = false;

// ── Validate token ─────────────────────────────────────────────
$stmt = $conn->prepare(
    "SELECT pr.id, pr.user_id, pr.expires_at, u.username
     FROM password_resets pr
     JOIN users u ON u.id = pr.user_id
     WHERE pr.token = ? AND pr.used = 0 AND pr.expires_at > NOW()
     LIMIT 1"
);
$stmt->bind_param("s", $token);
$stmt->execute();
$reset = $stmt->get_result()->fetch_assoc();
$stmt->close();

$tokenValid = ($reset !== null);

// ── Handle new password submission ─────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $tokenValid) {
    $newPassword = $_POST['new_password']     ?? '';
    $confirm     = $_POST['confirm_password'] ?? '';
    $ip          = $_SERVER['REMOTE_ADDR']    ?? 'unknown';

    if (strlen($newPassword) < 8) {
        $errors[] = "Password must be at least 8 characters.";
    }
    if ($newPassword !== $confirm) {
        $errors[] = "Passwords do not match.";
    }

    if (empty($errors)) {
        $hashed = password_hash($newPassword, PASSWORD_DEFAULT);

        // Update password
        $upd = $conn->prepare(
            "UPDATE users SET password = ? WHERE id = ?"
        );
        $upd->bind_param("si", $hashed, $reset['user_id']);
        $upd->execute();
        $upd->close();

        // Mark token as used
        $mark = $conn->prepare(
            "UPDATE password_resets SET used = 1 WHERE id = ?"
        );
        $mark->bind_param("i", $reset['id']);
        $mark->execute();
        $mark->close();

        audit_log($conn, $reset['user_id'], 'PASSWORD_RESET_COMPLETE',
            "Password reset completed for '{$reset['username']}' from $ip");

        $done = true;
    }
}

$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureAuth – Set New Password</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <div class="card">

    <div class="brand">
      <div class="brand-icon">🔐</div>
      <div class="brand-name">Secure<span>Auth</span></div>
    </div>

    <?php if ($done): ?>
      <h2>Password updated</h2>
      <div class="alert alert-success" style="margin-top:20px">
        <span class="alert-icon">✓</span>
        Your password has been changed successfully.
      </div>
      <div class="card-footer">
        <a href="index.php">Sign in with your new password →</a>
      </div>

    <?php elseif (!$tokenValid): ?>
      <h2>Invalid or expired link</h2>
      <div class="alert alert-danger" style="margin-top:20px">
        <span class="alert-icon">⚠</span>
        This reset link is invalid or has expired. Please request a new one.
      </div>
      <div class="card-footer">
        <a href="forgot_password.php">Request a new link</a>
      </div>

    <?php else: ?>
      <h2>Set new password</h2>
      <p class="subtitle">Choose a strong password for <strong><?php echo htmlspecialchars($reset['username']); ?></strong>.</p>

      <?php if (!empty($errors)): ?>
        <div class="alert alert-danger">
          <span class="alert-icon">⚠</span>
          <div>
            <?php foreach ($errors as $e): ?>
              <div><?php echo htmlspecialchars($e); ?></div>
            <?php endforeach; ?>
          </div>
        </div>
      <?php endif; ?>

      <form id="resetForm" action="reset_password.php" method="POST" novalidate>
        <input type="hidden" name="token" value="<?php echo htmlspecialchars($token); ?>">

        <div class="form-group">
          <label for="new_password">New password</label>
          <input type="password" id="new_password" name="new_password"
                 autocomplete="new-password" required>
          <div class="strength-bar">
            <div class="strength-fill" id="strengthFill"></div>
          </div>
          <p class="field-hint" id="strengthLabel"></p>
          <p class="field-hint err" id="newPassErr"></p>
        </div>

        <div class="form-group">
          <label for="confirm_password">Confirm new password</label>
          <input type="password" id="confirm_password" name="confirm_password"
                 autocomplete="new-password" required>
          <p class="field-hint err" id="confirmPassErr"></p>
        </div>

        <button type="submit" class="btn btn-primary">Update password</button>
      </form>
    <?php endif; ?>

  </div>
  <script src="script.js"></script>
</body>
</html>