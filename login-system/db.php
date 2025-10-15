<?php


define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'login_system');

$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);

if ($conn->connect_error) {
    // Don't expose raw DB errors to the browser in production
    error_log("DB connection failed: " . $conn->connect_error);
    die(json_encode(["error" => "Service temporarily unavailable. Please try again later."]));
}

$conn->set_charset("utf8mb4");