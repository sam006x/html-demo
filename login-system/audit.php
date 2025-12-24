<?php


function audit_log(mysqli $conn, ?int $userId, string $event, string $detail = ''): void {
    $ip        = $_SERVER['REMOTE_ADDR']     ?? 'unknown';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

    $stmt = $conn->prepare(
        "INSERT INTO audit_log (user_id, event, ip_address, user_agent, detail)
         VALUES (?, ?, ?, ?, ?)"
    );
    $stmt->bind_param("issss", $userId, $event, $ip, $userAgent, $detail);
    $stmt->execute();
    $stmt->close();
}
