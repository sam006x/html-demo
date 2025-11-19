<?php

session_start();
require_once 'db.php';
require_once 'audit.php';


if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit();
}

// Optional: bind session to IP (detects simple session hijacking)
if (isset($_SESSION['ip']) && $_SESSION['ip'] !== $_SERVER['REMOTE_ADDR']) {
    session_destroy();
    header("Location: index.php?warn=session");
    exit();
}

$userId   = (int) $_SESSION['user_id'];
$username = $_SESSION['username'];


$logStmt = $conn->prepare(
    "SELECT event, ip_address, created_at, detail
     FROM audit_log
     WHERE user_id = ?
     ORDER BY created_at DESC
     LIMIT 10"
);
$logStmt->bind_param("i", $userId);
$logStmt->execute();
$logs = $logStmt->get_result()->fetch_all(MYSQLI_ASSOC);
$logStmt->close();


$failStmt = $conn->prepare(
    "SELECT COUNT(*) AS cnt FROM audit_log
     WHERE user_id = ? AND event = 'LOGIN_FAIL'
     AND created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)"
);
$failStmt->bind_param("i", $userId);
$failStmt->execute();
$failCount = $failStmt->get_result()->fetch_assoc()['cnt'];
$failStmt->close();

$conn->close();


function eventIcon(string $event): string {
    return match (true) {
        str_contains($event, 'SUCCESS') => '✓',
        str_contains($event, 'FAIL')    => '✗',
        str_contains($event, 'LOGOUT')  => '→',
        str_contains($event, 'RESET')   => '⟳',
        str_contains($event, 'REGISTER')=> '★',
        default                         => '•',
    };
}
function eventDot(string $event): string {
    return match (true) {
        str_contains($event, 'SUCCESS') || str_contains($event, 'REGISTER') => 'dot-green',
        str_contains($event, 'FAIL')    || str_contains($event, 'BLOCKED')  => 'dot-red',
        default                                                              => 'dot-blue',
    };
}
function eventBadge(string $event): string {
    $cls = str_contains($event, 'FAIL') || str_contains($event, 'BLOCK')
         ? 'badge-danger' : 'badge-success';
    $label = str_replace('_', ' ', $event);
    return "<span class='badge $cls'>$label</span>";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureAuth – Dashboard</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <div class="card" style="max-width:520px">

    <!-- Header -->
    <div class="dash-header">
      <div style="display:flex;align-items:center;gap:12px">
        <div class="avatar">
          <?php echo strtoupper(substr($username, 0, 1)); ?>
        </div>
        <div>
          <div style="font-weight:600;font-size:15px">
            <?php echo htmlspecialchars($username); ?>
          </div>
          <div style="font-size:12px;color:var(--text-muted)">Authenticated session</div>
        </div>
      </div>
      <form action="logout.php" method="POST">
        <button type="submit" class="btn-ghost">Sign out</button>
      </form>
    </div>

    <!-- Stats -->
    <div class="stat-grid">
      <div class="stat-box">
        <div class="stat-label">Session status</div>
        <div class="stat-value green">Active</div>
      </div>
      <div class="stat-box">
        <div class="stat-label">Failed logins (7d)</div>
        <div class="stat-value <?php echo $failCount > 0 ? 'stat-value' : 'blue'; ?>"
             style="<?php echo $failCount > 0 ? 'color:var(--danger)' : ''; ?>">
          <?php echo (int)$failCount; ?>
        </div>
      </div>
    </div>

    <?php if ($failCount >= 3): ?>
      <div class="alert alert-warn" style="margin-bottom:20px">
        <span class="alert-icon">⚠</span>
        <?php echo $failCount; ?> failed login attempts on your account in the last 7 days.
        If this wasn't you, consider changing your password.
      </div>
    <?php endif; ?>

    <!-- Activity log -->
    <div style="font-size:13px;font-weight:600;color:var(--text-muted);
                letter-spacing:.4px;text-transform:uppercase;margin-bottom:14px">
      Recent Activity
    </div>

    <?php if (empty($logs)): ?>
      <p style="color:var(--text-muted);font-size:13px">No activity recorded yet.</p>
    <?php else: ?>
      <ul class="activity-list">
        <?php foreach ($logs as $log): ?>
          <li class="activity-item">
            <div class="activity-dot <?php echo eventDot($log['event']); ?>"></div>
            <div style="flex:1;min-width:0">
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
                <?php echo eventBadge($log['event']); ?>
                <span class="activity-time">
                  <?php echo htmlspecialchars(
                    date('d M Y, H:i', strtotime($log['created_at']))
                  ); ?>
                </span>
              </div>
              <div style="color:var(--text-muted);font-size:12px;margin-top:3px;
                          font-family:'DM Mono',monospace;">
                IP: <?php echo htmlspecialchars($log['ip_address']); ?>
                <?php if ($log['detail']): ?>
                  · <?php echo htmlspecialchars($log['detail']); ?>
                <?php endif; ?>
              </div>
            </div>
          </li>
        <?php endforeach; ?>
      </ul>
    <?php endif; ?>

  </div>
  <script src="script.js"></script>
</body>
</html>