<?php

session_start();
require_once 'db.php';
require_once 'audit.php';

// Already logged in?
if (isset($_SESSION['user_id'])) {
    header("Location: dashboard.php");
    exit();
}

// ── Constants ──────────────────────────────────────────────────
define('MAX_ATTEMPTS',   5);    // failed logins before lockout
define('LOCKOUT_SECS',   900);  // 15 minutes

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: index.php");
    exit();
}

// ── Collect & sanitise inputs ──────────────────────────────────
$username  = trim($_POST['username'] ?? '');
$password  = $_POST['password'] ?? '';
$ip        = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

// Basic presence validation (JS does this too, but never trust the client)
if ($username === '' || $password === '') {
    $_SESSION['message'] = "Please fill in all fields.";
    header("Location: index.php");
    exit();
}

// ── Brute-force / lockout check ────────────────────────────────
$window = date('Y-m-d H:i:s', time() - LOCKOUT_SECS);

$chk = $conn->prepare(
    "SELECT COUNT(*) AS attempts
     FROM login_attempts
     WHERE username = ? AND ip_address = ? AND attempted_at > ?"
);
$chk->bind_param("sss", $username, $ip, $window);
$chk->execute();
$attempts = $chk->get_result()->fetch_assoc()['attempts'];
$chk->close();

if ($attempts >= MAX_ATTEMPTS) {
    $remaining = ceil(LOCKOUT_SECS / 60);
    audit_log($conn, null, 'LOGIN_BLOCKED',
        "Blocked after $attempts attempts for user '$username'");
    $_SESSION['message'] = "Too many failed attempts. Please wait {$remaining} minutes before trying again.";
    header("Location: index.php");
    exit();
}

// ── Lookup user ────────────────────────────────────────────────
$stmt = $conn->prepare(
    "SELECT id, username, password, is_active FROM users WHERE username = ? LIMIT 1"
);
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();
$user   = $result->fetch_assoc();
$stmt->close();

// ── Verify password ────────────────────────────────────────────
$valid = $user && $user['is_active'] && password_verify($password, $user['password']);

if (!$valid) {
    // Log the failed attempt
    $fail = $conn->prepare(
        "INSERT INTO login_attempts (username, ip_address) VALUES (?, ?)"
    );
    $fail->bind_param("ss", $username, $ip);
    $fail->execute();
    $fail->close();

    audit_log($conn, $user['id'] ?? null, 'LOGIN_FAIL',
        "Failed login for '$username' from $ip");

    // Generic message – don't reveal whether username exists
    $left = MAX_ATTEMPTS - ($attempts + 1);
    $msg  = "Invalid username or password.";
    if ($left > 0 && $left <= 2) {
        $msg .= " ($left attempt" . ($left === 1 ? '' : 's') . " remaining before lockout.)";
    }
    $_SESSION['message'] = $msg;
    header("Location: index.php");
    exit();
}




session_regenerate_id(true);

$_SESSION['user_id']  = $user['id'];
$_SESSION['username'] = $user['username'];
$_SESSION['ip']       = $ip;                      // tie session to IP
$_SESSION['ua']       = $_SERVER['HTTP_USER_AGENT'] ?? '';

setcookie(
    "auth_token",
    bin2hex(random_bytes(16)),
    [
        'expires'  => time() + 3600,
        'path'     => '/',
        'secure'   => false,      
        'httponly' => true,       
        'samesite' => 'Strict'   
    ]
);

// Update last_login timestamp
$upd = $conn->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
$upd->bind_param("i", $user['id']);
$upd->execute();
$upd->close();

// Clear old failed attempts for this user on success
$clr = $conn->prepare(
    "DELETE FROM login_attempts WHERE username = ? AND ip_address = ?"
);
$clr->bind_param("ss", $username, $ip);
$clr->execute();
$clr->close();

audit_log($conn, $user['id'], 'LOGIN_SUCCESS', "Successful login from $ip");

$conn->close();
header("Location: dashboard.php");
exit();