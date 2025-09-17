<?php

session_start();
require_once 'db.php';
require_once 'audit.php';

$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $email    = trim($_POST['email']    ?? '');
    $password =      $_POST['password'] ?? '';
    $confirm  =      $_POST['confirm']  ?? '';



    if (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
        $errors[] = "Username must be 3–20 characters (letters, numbers, underscore only).";
    }


    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Please enter a valid email address.";
    }


    if (strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters long.";
    }

    
    if ($password !== $confirm) {
        $errors[] = "Passwords do not match.";
    }

    if (empty($errors)) {
        $hashed = password_hash($password, PASSWORD_DEFAULT);

        $stmt = $conn->prepare(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)"
        );
        $stmt->bind_param("sss", $username, $email, $hashed);

        if ($stmt->execute()) {
            $newId = $conn->insert_id;
            audit_log($conn, $newId, 'REGISTER',
                "New account created: '$username' from " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));

            $_SESSION['message_type'] = 'success';
            $_SESSION['message']      = "Account created successfully! You can now sign in.";
            $stmt->close();
            $conn->close();
            header("Location: index.php");
            exit();
        } else {
            $err = $stmt->error;
            $stmt->close();
            if (strpos($err, 'Duplicate') !== false) {
                if (strpos($err, 'username') !== false) {
                    $errors[] = "That username is already taken. Please choose another.";
                } else {
                    $errors[] = "An account with that email already exists.";
                }
            } else {
                error_log("Register error: $err");
                $errors[] = "Registration failed due to a server error. Please try again.";
            }
        }
    }
}

if (isset($conn) && $conn->ping()) 
    {
    $conn->close();
    }
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureAuth – Create Account</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <div class="card">

    <div class="brand">
      <div class="brand-icon">🔐</div>
      <div class="brand-name">Secure<span>Auth</span></div>
    </div>

    <h2>Create account</h2>
    <p class="subtitle">Fill in the details below to register.</p>

    <?php if (!empty($errors)): ?>
      
          <?php foreach ($errors as $e): ?>
            <div><?php echo htmlspecialchars($e); ?></div>
          <?php endforeach; ?>
        </div>
      </div>
    <?php endif; ?>

    <form id="registerForm" action="register.php" method="POST" novalidate>

      <div class="form-group">
        <label for="reg_username">Username</label>
        <input type="text" id="reg_username" name="username"
               value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>"
               autocomplete="username" required>
        <p class="field-hint err" id="regUsernameErr"></p>
        <p class="field-hint">3–20 chars · letters, numbers, underscore</p>
      </div>

      <div class="form-group">
        <label for="reg_email">Email address</label>
        <input type="email" id="reg_email" name="email"
               value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>"
               autocomplete="email" required>
        <p class="field-hint err" id="regEmailErr"></p>
      </div>

      <div class="form-group">
        <label for="reg_password">Password:</label>
        <input type="password" id="reg_password" name="password"
               autocomplete="new-password" required>
        <div class="strength-bar">
          <div class="strength-fill" id="strengthFill"></div>
        </div>

        <p class="field-hint" id="strengthLabel"></p>
        <p class="field-hint err" id="regPasswordErr"></p>
      </div>

      <div class="form-group">
        <label for="reg_confirm">Confirm password</label>
        <input type="password" id="reg_confirm" name="confirm"
               autocomplete="new-password" required>
        <p class="field-hint err" id="regConfirmErr"></p>
      </div>

      <button type="submit" class="btn btn-primary" id="regSubmitBtn">Create account</button>
    </form>

    <div class="card-footer">
      Already have an account? <a href="index.php">Sign in</a>
    </div>
  </div>

  <script src="script.js"></script>
</body>
</html>