# SecureAuth — PHP Login & Registration System

A secure, full-stack authentication system built with PHP, MySQL, HTML, CSS and JavaScript. 


## Features

| Feature | Details |
|---|---|
| **User Registration** | Server-side validation, email field, bcrypt password hashing |
| **Secure Login** | Prepared statements (SQL injection prevention), session hardening |
| **Brute-force Protection** | Lockout after 5 failed attempts per IP per 15 minutes |
| **Password Reset Flow** | Cryptographically secure token (32 random bytes), 1-hour expiry, single-use |
| **Audit Logging** | Every login, failure, logout and reset is logged with IP and timestamp |
| **Session Security** | ID regeneration on login, IP binding, HttpOnly + Secure + SameSite cookies |
| **Input Validation** | Both client-side (JS) and server-side (PHP) on all forms |
| **Password Strength Meter** | Live feedback on register and reset forms |

---

## Security Controls

```
✓ Parameterised queries          — prevents SQL injection
✓ password_hash / password_verify — bcrypt, no plaintext storage
✓ session_regenerate_id(true)    — prevents session fixation
✓ HttpOnly + Secure + SameSite   — cookie hardening
✓ Login attempt rate limiting    — brute-force mitigation
✓ Generic error messages         — prevents username enumeration
✓ Server-side input validation   — cannot be bypassed like client-side
✓ Audit trail table              — access monitoring, incident response
✓ Reset token expiry + one-use   — secure password recovery
```

---

## Project Structure

```
login_system/
├── index.html          # Login page
├── register.php        # Registration form + handler
├── login.php           # Login handler (auth logic lives here)
├── dashboard.php       # Protected page with activity log
├── logout.php          # Session teardown
├── forgot_password.php # Password reset request
├── reset_password.php  # Token validation + new password
├── audit.php           # Shared audit logging function
├── db.php              # Database connection (single source of truth)
├── schema.sql          # Full DB schema (run once to set up)
├── style.css           # Dark-themed responsive UI
└── script.js           # Client-side validation (all forms)
```

---

## Setup

### Requirements
- PHP 8.0+
- MySQL 5.7+ / MariaDB 10.4+
- A local server (XAMPP, Laragon, WAMP, etc.)

### Steps

```bash
# 1. Clone or copy the project into your server's web root
#    e.g. C:/xampp/htdocs/login_system/

# 2. Create the database and tables
mysql -u root instant-login < schema.sql

# 3. Edit db.php if your MySQL credentials differ from the defaults
#    DB_USER = 'root', DB_PASS = '', DB_NAME = 'instant-login'

# 4. Visit http://localhost/instant-login/
```

---

## Database Schema

| Table | Purpose |
|---|---|
| `users` | Stores accounts: username, email, hashed password, last login |
| `login_attempts` | Records failed logins per username + IP for rate limiting |
| `audit_log` | Full event log: login, logout, failures, resets, registrations |
| `password_resets` | Stores one-time reset tokens with expiry |

---

## What I Learned

Building this system pushed me beyond basic web development into practical application security:

- Why prepared statements matter and how SQL injection actually works
- How bcrypt hashing prevents offline password attacks even if a DB is leaked
- The difference between authentication-you are who you say and authorisation- you can do what you are trying to do
- How session fixation attacks work and why `session_regenerate_id()` is important
- How audit trails support incident response — you can't investigate what you didn't log
