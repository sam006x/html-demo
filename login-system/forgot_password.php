<?php

session_start();
require_once 'db.php';
require_once 'audit.php';

$tokenGenerated = null;
$errors         = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $ip    = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Please enter a valid email address.";
    } else {
        // Always show success even if email not found (prevents enumeration)
        $stmt = $conn->prepare(
            "SELECT id, username FROM users WHERE email = ? AND is_active = 1 LIMIT 1"
        );
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if ($user) {
            // Invalidate any existing tokens for this user
            $del = $conn->prepare(
                "DELETE FROM password_resets WHERE user_id = ?"
            );
            $del->bind_param("i", $user['id']);
            $del->execute();
            $del->close();

            // Generate a cryptographically secure token
            $token     = bin2hex(random_bytes(32));   // 64 hex chars
            $expiresAt = date('Y-m-d H:i:s', time() + 3600); // 1 hour

            $ins = $conn->prepare(
                "INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)"
            );
            $ins->bind_param("iss", $user['id'], $token, $expiresAt);
            $ins->execute();
            $ins->close();

            audit_log($conn, $user['id'], 'PASSWORD_RESET_REQUEST',
                "Reset requested for '{$user['username']}' from $ip");

            // In production: send $token via email.
            // For demo we surface it on screen with a note.
            $tokenGenerated = $token;
        }
        // No else – we don't reveal whether the email exists
    }
}

$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureAuth – Reset Password</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <div class="card">

    <div class="brand">
      <div class="brand-icon">🔐</div>
      <div class="brand-name">Secure<span>Auth</span></div>
    </div>

    <h2>Reset password</h2>
    <p class="subtitle">Enter your registered email address and we'll send you a reset link.</p>

    <?php if (!empty($errors)): ?>
      <div class="alert alert-danger">
        <span class="alert-icon">⚠</span>
        <?php echo htmlspecialchars($errors[0]); ?>
      </div>
    <?php endif; ?>

    <?php if ($tokenGenerated): ?>
      <!-- 
        DEMO MODE: In production this token would be sent by email.
        We display it here only to demonstrate the token generation flow.
      -->
      <div class="alert alert-success">
        <span class="alert-icon">✓</span>
        <div>
          <strong>Reset link generated!</strong><br>
          <em>(In production this would be emailed to you.)</em><br><br>
          <strong>Demo token:</strong><br>
          <code style="font-family:'DM Mono',monospace;font-size:11px;word-break:break-all;">
            <?php echo htmlspecialchars($tokenGenerated); ?>
          </code><br><br>
          <a href="reset_password.php?token=<?php echo urlencode($tokenGenerated); ?>">
            → Click here to reset your password
          </a>
          <br>
          <small style="color:var(--text-muted)">Token expires in 1 hour.</small>
        </div>
      </div>
    <?php elseif ($_SERVER['REQUEST_METHOD'] === 'POST'): ?>
      <div class="alert alert-success">
        <span class="alert-icon">✓</span>
        If that email is registered, a reset link has been sent.
      </div>
    <?php else: ?>
      <form id="forgotForm" action="forgot_password.php" method="POST" novalidate>
        <div class="form-group">
          <label for="email">Email address</label>
          <input type="email" id="email" name="email"
                 autocomplete="email" required>
          <p class="field-hint err" id="emailErr"></p>
        </div>
        <button type="submit" class="btn btn-primary" id="forgotBtn">Send reset link</button>
      </form>
    <?php endif; ?>

    <div class="card-footer">
      <a href="index.php">← Back to sign in</a>
    </div>
  </div>
  <script src="script.js"></script>
</body>
</html>