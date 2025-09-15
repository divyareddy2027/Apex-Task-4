<?php
/**
 * Single-file PHP example implementing:
 * - PDO prepared statements
 * - Server-side form validation (and simple client-side validation)
 * - Role-based access control (user roles: user, editor, admin)
 *
 * Instructions:
 * 1. Create a MySQL database and run the SQL below once to create the users table.
 * 2. Configure DB settings in $dbConfig.
 * 3. Place this file in your webroot (e.g., htdocs in XAMPP) and open in browser.
 *
 * SQL (run in MySQL):
 *
 * CREATE DATABASE lead_app CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
 * USE lead_app;
 * CREATE TABLE users (
 *   id INT AUTO_INCREMENT PRIMARY KEY,
 *   name VARCHAR(100) NOT NULL,
 *   email VARCHAR(255) NOT NULL UNIQUE,
 *   password_hash VARCHAR(255) NOT NULL,
 *   role ENUM('user','editor','admin') NOT NULL DEFAULT 'user',
 *   created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
 * ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
 *
 * You can insert an admin with:
 * INSERT INTO users (name, email, password_hash, role) VALUES
 * ('Admin','admin@example.com','[PUT_HASH_HERE]','admin');
 * To create a hash manually in PHP CLI: <?php echo password_hash('yourpassword', PASSWORD_DEFAULT);
 */

/* ---------------------- Configuration ---------------------- */
session_start();

$dbConfig = [
    'host' => '127.0.0.1',
    'port' => '3306',
    'dbname' => 'lead_app',
    'user' => 'root',
    'pass' => '', // <-- set your DB password
    'charset' => 'utf8mb4',
];

try {
    $dsn = "mysql:host={$dbConfig['host']};dbname={$dbConfig['dbname']};charset={$dbConfig['charset']};port={$dbConfig['port']}";
    $pdo = new PDO($dsn, $dbConfig['user'], $dbConfig['pass'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (PDOException $e) {
    http_response_code(500);
    exit("Database connection failed: " . htmlspecialchars($e->getMessage()));
}

/* ---------------------- Helpers ---------------------- */

function generate_csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf_token($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], (string)$token);
}

function is_logged_in() {
    return !empty($_SESSION['user']);
}

function current_user() {
    return $_SESSION['user'] ?? null;
}

function require_login() {
    if (!is_logged_in()) {
        header('Location: ?page=login');
        exit;
    }
}

function check_role($allowed_roles = []) {
    $user = current_user();
    if (!$user) return false;
    return in_array($user['role'], (array)$allowed_roles, true);
}

/* ---------------------- Actions: Register / Login / Logout ---------------------- */

$page = $_GET['page'] ?? 'home';
$errors = [];
$old = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Protect against CSRF for all sensitive POST actions
    $post_csrf = $_POST['csrf_token'] ?? '';
    if (!verify_csrf_token($post_csrf)) {
        $errors[] = "Invalid CSRF token. Try refreshing the page.";
    } else {
        if (($page === 'register') && empty($errors)) {
            // Server-side validation for registration
            $name  = trim($_POST['name'] ?? '');
            $email = trim($_POST['email'] ?? '');
            $pass  = $_POST['password'] ?? '';
            $pass2 = $_POST['password_confirm'] ?? '';

            $old['name'] = htmlspecialchars($name);
            $old['email'] = htmlspecialchars($email);

            if (mb_strlen($name) < 2) $errors[] = "Name must be at least 2 characters.";
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = "Invalid email address.";
            if (mb_strlen($pass) < 8) $errors[] = "Password must be at least 8 characters.";
            if ($pass !== $pass2) $errors[] = "Passwords do not match.";

            if (empty($errors)) {
                // Use prepared statements (PDO) to store user
                $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
                $stmt->execute([':email' => $email]);
                if ($stmt->fetch()) {
                    $errors[] = "Email is already registered.";
                } else {
                    $password_hash = password_hash($pass, PASSWORD_DEFAULT);
                    $insert = $pdo->prepare("INSERT INTO users (name, email, password_hash, role) VALUES (:name, :email, :password_hash, :role)");
                    // default role = user, but an admin could set other roles separately
                    $insert->execute([
                        ':name' => $name,
                        ':email' => $email,
                        ':password_hash' => $password_hash,
                        ':role' => 'user',
                    ]);
                    // Auto-login the new user
                    $uid = $pdo->lastInsertId();
                    $u = $pdo->prepare("SELECT id, name, email, role FROM users WHERE id = :id");
                    $u->execute([':id' => $uid]);
                    $_SESSION['user'] = $u->fetch();
                    header('Location: ?page=dashboard');
                    exit;
                }
            }
        }

        if (($page === 'login') && empty($errors)) {
            $email = trim($_POST['email'] ?? '');
            $pass  = $_POST['password'] ?? '';
            $old['email'] = htmlspecialchars($email);

            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = "Enter a valid email.";
            if ($pass === '') $errors[] = "Enter your password.";

            if (empty($errors)) {
                // Prepared statement to fetch user by email
                $stmt = $pdo->prepare("SELECT id, name, email, password_hash, role FROM users WHERE email = :email LIMIT 1");
                $stmt->execute([':email' => $email]);
                $user = $stmt->fetch();
                if (!$user || !password_verify($pass, $user['password_hash'])) {
                    $errors[] = "Invalid email or password.";
                } else {
                    // Successful login
                    unset($user['password_hash']);
                    $_SESSION['user'] = $user;
                    header('Location: ?page=dashboard');
                    exit;
                }
            }
        }

        if ($page === 'logout') {
            session_unset();
            session_destroy();
            session_start();
            header('Location: ?page=login');
            exit;
        }

        // Example: Admin can change a user's role (role management)
        if ($page === 'change_role' && empty($errors)) {
            require_login();
            if (!check_role(['admin'])) {
                $errors[] = "Forbidden: admin only.";
            } else {
                $target_id = intval($_POST['user_id'] ?? 0);
                $new_role = $_POST['role'] ?? '';
                $allowed = ['user','editor','admin'];
                if (!in_array($new_role, $allowed, true)) $errors[] = "Invalid role.";
                if ($target_id <= 0) $errors[] = "Invalid user id.";
                if (empty($errors)) {
                    $up = $pdo->prepare("UPDATE users SET role = :role WHERE id = :id");
                    $up->execute([':role' => $new_role, ':id' => $target_id]);
                    header('Location: ?page=admin&msg=role_updated');
                    exit;
                }
            }
        }
    }
}

/* ---------------------- Simple Router / Views ---------------------- */

$csrf = generate_csrf_token();

function esc($s) { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure Demo App</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;margin:0;padding:0;background:#f4f6f8;color:#111}
.container{max-width:900px;margin:32px auto;padding:20px;background:#fff;border-radius:8px;box-shadow:0 4px 14px rgba(0,0,0,.06)}
.header{display:flex;justify-content:space-between;align-items:center}
nav a{margin-right:12px;text-decoration:none;color:#0366d6}
form{margin-top:16px}
input,select{display:block;width:100%;padding:8px;margin:8px 0;border-radius:6px;border:1px solid #ccc}
button{padding:8px 12px;border-radius:6px;border:0;background:#0366d6;color:#fff;cursor:pointer}
.error{background:#ffe6e6;padding:10px;border-radius:6px;color:#a00;margin:10px 0}
.success{background:#e6ffea;padding:10px;border-radius:6px;color:#070;margin:10px 0}
.small{font-size:0.9rem;color:#666}
.user-card{padding:12px;border-radius:6px;border:1px solid #eee;margin:8px 0}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>Secure Demo App</h1>
    <div>
      <?php if (is_logged_in()): ?>
        Hello, <strong><?= esc(current_user()['name']); ?></strong> (<?= esc(current_user()['role']); ?>) |
        <a href="?page=dashboard">Dashboard</a>
        <?php if (check_role(['admin'])): ?><a href="?page=admin">Admin</a><?php endif; ?>
        <a href="?page=logout" onclick="event.preventDefault(); document.getElementById('logout-form').submit();">Logout</a>
        <form id="logout-form" method="post" action="?page=logout" style="display:none;">
          <input type="hidden" name="csrf_token" value="<?= esc($csrf); ?>">
        </form>
      <?php else: ?>
        <a href="?page=login">Login</a> <a href="?page=register">Register</a>
      <?php endif; ?>
    </div>
  </div>

  <?php if (!empty($errors)): ?>
    <div class="error">
      <?php foreach ($errors as $e) echo '<div>' . esc($e) . '</div>'; ?>
    </div>
  <?php endif; ?>

  <?php
  // Simple pages
  if ($page === 'home'): ?>
      <p>Welcome. This demo shows secure patterns: prepared statements (PDO), server-side validation and role-based access control.</p>

  <?php elseif ($page === 'register'): ?>
      <h2>Register</h2>
      <form method="post" action="?page=register" novalidate onsubmit="return clientValidateRegister(this);">
        <input type="hidden" name="csrf_token" value="<?= esc($csrf); ?>">
        <label>Name <input name="name" required minlength="2" value="<?= $old['name'] ?? '' ?>"></label>
        <label>Email <input name="email" type="email" required value="<?= $old['email'] ?? '' ?>"></label>
        <label>Password <input name="password" type="password" required minlength="8" ></label>
        <label>Confirm Password <input name="password_confirm" type="password" required minlength="8"></label>
        <button type="submit">Register</button>
      </form>
      <p class="small">Client-side validation is optional and for UX; server-side validation is authoritative.</p>

      <script>
      function clientValidateRegister(form){
        // example client validation (not a substitute for server-side checks)
        if (form.password.value.length < 8) { alert('Password too short'); return false; }
        if (form.password.value !== form.password_confirm.value) { alert('Passwords do not match'); return false; }
        return true;
      }
      </script>

  <?php elseif ($page === 'login'): ?>
      <h2>Login</h2>
      <form method="post" action="?page=login" novalidate>
        <input type="hidden" name="csrf_token" value="<?= esc($csrf); ?>">
        <label>Email <input name="email" type="email" required value="<?= $old['email'] ?? '' ?>"></label>
        <label>Password <input name="password" type="password" required></label>
        <button type="submit">Login</button>
      </form>
      <p class="small">If you lost access, reset by DB or build a reset flow.</p>

  <?php elseif ($page === 'dashboard'): ?>
      <?php require_login(); ?>
      <h2>Dashboard</h2>
      <p>Secure area for logged users. Your role determines access to admin functions.</p>

      <div class="user-card">
        <strong>Your info</strong><br>
        ID: <?= esc(current_user()['id'] ?? 'N/A'); ?><br>
        Name: <?= esc(current_user()['name']); ?><br>
        Email: <?= esc(current_user()['email']); ?><br>
        Role: <?= esc(current_user()['role']); ?><br>
      </div>

      <?php if (check_role(['admin','editor'])): ?>
        <h3>Editor/Admin tools</h3>
        <p class="small">Example protected content for editor/admin.</p>
      <?php endif; ?>

  <?php elseif ($page === 'admin'): ?>
      <?php require_login(); if (!check_role(['admin'])): ?>
        <div class="error">Forbidden. Admins only.</div>
      <?php else: ?>
        <h2>Admin Panel</h2>
        <p>Manage user roles.</p>
        <?php
          // Fetch users safely
          $users = $pdo->query("SELECT id, name, email, role, created_at FROM users ORDER BY id DESC LIMIT 200")->fetchAll();
        ?>
        <?php foreach ($users as $u): ?>
          <div class="user-card">
            <strong><?= esc($u['name']); ?></strong> &nbsp; (<?= esc($u['email']); ?>) <br>
            Role: <?= esc($u['role']); ?> &nbsp; Created: <?= esc($u['created_at']); ?><br>
            <form method="post" action="?page=change_role" style="margin-top:8px">
              <input type="hidden" name="csrf_token" value="<?= esc($csrf); ?>">
              <input type="hidden" name="user_id" value="<?= esc($u['id']); ?>">
              <select name="role" aria-label="Role for <?= esc($u['name']); ?>">
                <option value="user" <?= $u['role']==='user' ? 'selected' : '' ?>>user</option>
                <option value="editor" <?= $u['role']==='editor' ? 'selected' : '' ?>>editor</option>
                <option value="admin" <?= $u['role']==='admin' ? 'selected' : '' ?>>admin</option>
              </select>
              <button type="submit">Change Role</button>
            </form>
          </div>
        <?php endforeach; ?>
      <?php endif; ?>

  <?php elseif ($page === 'change_role'): ?>
      <?php
        // This code path is handled in POST earlier; if got here via GET, redirect to admin
        header('Location: ?page=admin');
        exit;
      ?>

  <?php else: ?>
      <h2>Page not found</h2>
      <p><a href="?page=home">Go home</a></p>
  <?php endif; ?>

  <hr>
  <small class="small">Security highlights:
    <ul>
      <li>Database queries use PDO prepared statements to prevent SQL injection.</li>
      <li>Server-side validation ensures data integrity even if client-side is bypassed.</li>
      <li>CSRF protection via tokens for state-changing requests.</li>
      <li>Password hashing via password_hash / password_verify.</li>
      <li>Role-based access control checks before privileged actions.</li>
    </ul>
  </small>
</div>
</body>
</html>
