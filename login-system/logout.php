<?php

session_start();
require_once 'db.php';
require_once 'audit.php';

if (isset($_SESSION['user_id'])) {
    audit_log($conn, (int)$_SESSION['user_id'], 'LOGOUT',
        "User '{$_SESSION['username']}' signed out");
}

$conn->close();

// Wipe session data
$_SESSION = [];
session_destroy();

// Delete the auth cookie
setcookie("auth_token", "", [
    'expires'  => time() - 3600,
    'path'     => '/',
    'secure'   => false,
    'httponly' => true,
    'samesite' => 'Strict'
]);

header("Location: index.php");
exit();
