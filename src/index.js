import {
  hashPassword,
  verifyPassword,
  generateOTP,
  hashOTP,
  createSessionToken,
  verifySessionToken,
  generateDeviceToken,
} from "./auth.js";
import { sendOTPEmail } from "./email.js";

const OTP_TTL_MS = 10 * 60 * 1000; // 10 minutes

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

// Rough, dependency-free guess at "Browser on OS" from the User-Agent header.
// Good enough as a default label -- a real rename option comes later with
// the Trusted Devices settings screen.
function guessDeviceName(userAgent) {
  if (!userAgent) return "Unknown device";

  let os = "Unknown OS";
  if (userAgent.includes("Windows")) os = "Windows";
  else if (userAgent.includes("Mac OS")) os = "Mac";
  else if (userAgent.includes("Android")) os = "Android";
  else if (userAgent.includes("iPhone") || userAgent.includes("iPad")) os = "iOS";
  else if (userAgent.includes("Linux")) os = "Linux";

  let browser = "Unknown browser";
  if (userAgent.includes("Edg/")) browser = "Edge";
  else if (userAgent.includes("Chrome/")) browser = "Chrome";
  else if (userAgent.includes("Firefox/")) browser = "Firefox";
  else if (userAgent.includes("Safari/")) browser = "Safari";

  return `${browser} on ${os}`;
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(";").forEach((pair) => {
    const [key, ...rest] = pair.trim().split("=");
    cookies[key] = rest.join("=");
  });
  return cookies;
}

// Reads the session cookie, verifies it, and loads the current user from
// the database. Returns null if not logged in, session expired, or the
// account has since been deactivated.
async function getCurrentUser(request, env) {
  const cookies = parseCookies(request.headers.get("Cookie"));
  if (!cookies.session) return null;

  const userId = await verifySessionToken(cookies.session, env.SESSION_SECRET);
  if (!userId) return null;

  const user = await env.DB.prepare(
    "SELECT id, name, email, role, password_hash, pin_hash, is_active FROM users WHERE id = ?"
  )
    .bind(userId)
    .first();

  if (!user || !user.is_active) return null;
  return user;
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);

      if (request.method === "GET" && url.pathname === "/") {
        return new Response(HTML_PAGE, { headers: { "content-type": "text/html" } });
      }

      if (request.method === "POST" && url.pathname === "/api/setup") {
        return handleSetup(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/login") {
        return handleLogin(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/verify-otp") {
        return handleVerifyOtp(request, env);
      }

      if (request.method === "GET" && url.pathname === "/api/me") {
        return handleMe(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/set-pin") {
        return handleSetPin(request, env);
      }

      return new Response("Not found", { status: 404 });
    } catch (err) {
      // Catches anything unexpected so the browser always gets readable JSON
      // back instead of Cloudflare's generic HTML error page. The real
      // detail still shows up in `wrangler tail` either way.
      console.error("Unhandled error:", err);
      return new Response(JSON.stringify({ error: "Something went wrong on our end." }), {
        status: 500,
        headers: { "content-type": "application/json" },
      });
    }
  },
};

async function handleSetup(request, env) {
  const { name, email, password } = await request.json();

  if (!name || !email || !password) {
    return jsonResponse({ error: "Name, email, and password are required." }, 400);
  }
  if (password.length < 8) {
    return jsonResponse({ error: "Password must be at least 8 characters." }, 400);
  }

  // Only one owner account is allowed to be created this way -- this endpoint
  // is for the very first setup, not for adding more staff later.
  const existingOwner = await env.DB.prepare(
    "SELECT id FROM users WHERE role = 'owner' LIMIT 1"
  ).first();
  if (existingOwner) {
    return jsonResponse({ error: "An owner account already exists for this business." }, 403);
  }

  const existingEmail = await env.DB.prepare("SELECT id FROM users WHERE email = ?")
    .bind(email)
    .first();
  if (existingEmail) {
    return jsonResponse({ error: "That email is already registered." }, 400);
  }

  const passwordHash = await hashPassword(password);

  const result = await env.DB.prepare(
    "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'owner')"
  )
    .bind(name, email, passwordHash)
    .run();

  const userId = result.meta.last_row_id;

  const otp = generateOTP();
  const otpHash = await hashOTP(otp);
  const expiresAt = new Date(Date.now() + OTP_TTL_MS).toISOString();

  await env.DB.prepare(
    "INSERT INTO otp_codes (user_id, code_hash, purpose, expires_at) VALUES (?, ?, 'login', ?)"
  )
    .bind(userId, otpHash, expiresAt)
    .run();

  const emailSent = await sendOTPEmail(env, email, otp);
  if (!emailSent) {
    return jsonResponse(
      { error: "Account created, but the verification email failed to send. Contact support." },
      500
    );
  }

  return jsonResponse({ success: true, email });
}

async function handleLogin(request, env) {
  const { email, password } = await request.json();

  if (!email || !password) {
    return jsonResponse({ error: "Email and password are required." }, 400);
  }

  const user = await env.DB.prepare(
    "SELECT id, password_hash, is_active FROM users WHERE email = ?"
  )
    .bind(email)
    .first();

  // Same generic message whether the email doesn't exist or the password is
  // wrong -- this avoids confirming to an attacker which emails are registered.
  const invalidCredentials = () => jsonResponse({ error: "Invalid email or password." }, 400);

  if (!user || !user.is_active) {
    return invalidCredentials();
  }

  const validPassword = await verifyPassword(password, user.password_hash);
  if (!validPassword) {
    return invalidCredentials();
  }

  // Check whether this browser already carries a trusted device cookie.
  const cookies = parseCookies(request.headers.get("Cookie"));
  let trustedDevice = null;
  if (cookies.device) {
    trustedDevice = await env.DB.prepare(
      "SELECT id FROM trusted_devices WHERE device_token = ? AND is_active = 1"
    )
      .bind(cookies.device)
      .first();
  }

  const now = new Date().toISOString();

  if (trustedDevice) {
    // Trusted device -- log straight in, no OTP needed.
    await env.DB.prepare("UPDATE trusted_devices SET last_used_at = ? WHERE id = ?")
      .bind(now, trustedDevice.id)
      .run();
    await env.DB.prepare("UPDATE users SET last_login_at = ? WHERE id = ?").bind(now, user.id).run();
    await env.DB.prepare(
      "INSERT INTO audit_log (user_id, action, entity_type, entity_id) VALUES (?, 'login', 'user', ?)"
    )
      .bind(user.id, user.id)
      .run();

    const sessionToken = await createSessionToken(user.id, env.SESSION_SECRET);
    const headers = new Headers({ "content-type": "application/json" });
    headers.append(
      "Set-Cookie",
      `session=${sessionToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=43200`
    );
    return new Response(JSON.stringify({ success: true, trusted: true }), { headers });
  }

  // New or unrecognized device -- fall back to email OTP, same as setup does.
  const otp = generateOTP();
  const otpHash = await hashOTP(otp);
  const expiresAt = new Date(Date.now() + OTP_TTL_MS).toISOString();

  await env.DB.prepare(
    "INSERT INTO otp_codes (user_id, code_hash, purpose, expires_at) VALUES (?, ?, 'login', ?)"
  )
    .bind(user.id, otpHash, expiresAt)
    .run();

  const emailSent = await sendOTPEmail(env, email, otp);
  if (!emailSent) {
    return jsonResponse({ error: "Could not send the verification email. Try again." }, 500);
  }

  return jsonResponse({ success: true, otp_required: true, email });
}

async function handleVerifyOtp(request, env) {
  const { email, code } = await request.json();

  if (!email || !code) {
    return jsonResponse({ error: "Email and code are required." }, 400);
  }

  const user = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
  if (!user) {
    return jsonResponse({ error: "Invalid email or code." }, 400);
  }

  const otpHash = await hashOTP(code);
  const now = new Date().toISOString();

  const otpRow = await env.DB.prepare(
    `SELECT id FROM otp_codes
     WHERE user_id = ? AND code_hash = ? AND purpose = 'login'
       AND used_at IS NULL AND expires_at > ?
     ORDER BY id DESC LIMIT 1`
  )
    .bind(user.id, otpHash, now)
    .first();

  if (!otpRow) {
    return jsonResponse({ error: "Invalid or expired code." }, 400);
  }

  await env.DB.prepare("UPDATE otp_codes SET used_at = ? WHERE id = ?").bind(now, otpRow.id).run();

  const deviceToken = generateDeviceToken();
  const deviceName = guessDeviceName(request.headers.get("User-Agent"));
  await env.DB.prepare(
    "INSERT INTO trusted_devices (device_token, device_name, verified_by, last_used_at) VALUES (?, ?, ?, ?)"
  )
    .bind(deviceToken, deviceName, user.id, now)
    .run();

  await env.DB.prepare("UPDATE users SET last_login_at = ? WHERE id = ?").bind(now, user.id).run();

  await env.DB.prepare(
    "INSERT INTO audit_log (user_id, action, entity_type, entity_id) VALUES (?, 'login', 'user', ?)"
  )
    .bind(user.id, user.id)
    .run();

  const sessionToken = await createSessionToken(user.id, env.SESSION_SECRET);

  const headers = new Headers({ "content-type": "application/json" });
  headers.append(
    "Set-Cookie",
    `session=${sessionToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=43200`
  );
  headers.append(
    "Set-Cookie",
    `device=${deviceToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=31536000`
  );

  return new Response(JSON.stringify({ success: true }), { headers });
}

async function handleMe(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  return jsonResponse({
    id: currentUser.id,
    name: currentUser.name,
    email: currentUser.email,
    role: currentUser.role,
    has_pin: !!currentUser.pin_hash,
  });
}

async function handleSetPin(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }

  const { password, pin } = await request.json();

  if (!password || !pin) {
    return jsonResponse({ error: "Password and PIN are required." }, 400);
  }
  if (!/^\d{6}$/.test(pin)) {
    return jsonResponse({ error: "PIN must be exactly 6 digits." }, 400);
  }

  // Step-up check: setting a PIN is security-sensitive, so even though this
  // user already has a valid session, we require the real password again
  // before making the change -- same rule that will guard voids, refunds,
  // and settings changes later.
  const validPassword = await verifyPassword(password, currentUser.password_hash);
  if (!validPassword) {
    return jsonResponse({ error: "Incorrect password." }, 400);
  }

  const pinHash = await hashPassword(pin); // same PBKDF2 hashing reused for the PIN

  await env.DB.prepare(
    "UPDATE users SET pin_hash = ?, pin_failed_attempts = 0, pin_locked_until = NULL WHERE id = ?"
  )
    .bind(pinHash, currentUser.id)
    .run();

  await env.DB.prepare(
    "INSERT INTO audit_log (user_id, action, entity_type, entity_id) VALUES (?, 'pin_set', 'user', ?)"
  )
    .bind(currentUser.id, currentUser.id)
    .run();

  return jsonResponse({ success: true });
}

const HTML_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HarminPOS</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 400px; margin: 60px auto; padding: 0 20px; color: #1a1a1a; }
  h1 { font-size: 20px; margin-bottom: 4px; }
  p.sub { color: #666; margin-top: 0; margin-bottom: 24px; }
  label { display: block; margin-top: 16px; margin-bottom: 4px; font-size: 14px; font-weight: 600; }
  input { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 6px; font-size: 14px; box-sizing: border-box; }
  button { margin-top: 24px; width: 100%; padding: 12px; background: #1a1a1a; color: white; border: none; border-radius: 6px; font-size: 14px; cursor: pointer; }
  .error { color: #c0392b; margin-top: 12px; font-size: 14px; }
  .success { color: #27ae60; margin-top: 12px; font-size: 14px; }
  .toggle { margin-top: 16px; font-size: 13px; color: #666; text-align: center; }
  .toggle a { color: #1a1a1a; cursor: pointer; text-decoration: underline; }
  #loginSection, #otpSection, #pinSetupSection { display: none; }
</style>
</head>
<body>
  <div id="setupSection">
    <h1>Set up HarminPOS</h1>
    <p class="sub">Create the owner account for this business.</p>
    <label for="name">Your name</label>
    <input id="name" type="text" />
    <label for="email">Email</label>
    <input id="email" type="email" />
    <label for="password">Password</label>
    <input id="password" type="password" />
    <button id="setupBtn">Create account</button>
    <div id="setupMsg"></div>
    <p class="toggle">Already set up? <a id="showLogin">Log in instead</a></p>
  </div>

  <div id="loginSection">
    <h1>Log in to HarminPOS</h1>
    <p class="sub">Enter your email and password.</p>
    <label for="loginEmail">Email</label>
    <input id="loginEmail" type="email" />
    <label for="loginPassword">Password</label>
    <input id="loginPassword" type="password" />
    <button id="loginBtn">Log in</button>
    <div id="loginMsg"></div>
  </div>

  <div id="otpSection">
    <h1>Check your email</h1>
    <p class="sub">Enter the 6-digit code we sent you.</p>
    <label for="otp">Verification code</label>
    <input id="otp" type="text" maxlength="6" />
    <button id="verifyBtn">Verify</button>
    <div id="otpMsg"></div>
  </div>

  <div id="pinSetupSection">
    <h1>Set your PIN</h1>
    <p class="sub">A 6-digit PIN lets you log in fast on this device next time, no email code needed.</p>
    <label for="confirmPassword">Confirm your password</label>
    <input id="confirmPassword" type="password" />
    <label for="newPin">6-digit PIN</label>
    <input id="newPin" type="text" maxlength="6" inputmode="numeric" />
    <button id="setPinBtn">Save PIN</button>
    <div id="pinSetupMsg"></div>
  </div>

<script>
let pendingEmail = "";

function showOnly(id) {
  ["setupSection", "loginSection", "otpSection", "pinSetupSection"].forEach((sectionId) => {
    document.getElementById(sectionId).style.display = sectionId === id ? "block" : "none";
  });
}

document.getElementById("showLogin").addEventListener("click", () => showOnly("loginSection"));

document.getElementById("setupBtn").addEventListener("click", async () => {
  const name = document.getElementById("name").value.trim();
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;
  const msg = document.getElementById("setupMsg");
  msg.textContent = "";

  const res = await fetch("/api/setup", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name, email, password }),
  });
  const data = await res.json();

  if (!res.ok) {
    msg.textContent = data.error;
    msg.className = "error";
    return;
  }

  pendingEmail = email;
  showOnly("otpSection");
});

document.getElementById("loginBtn").addEventListener("click", async () => {
  const email = document.getElementById("loginEmail").value.trim();
  const password = document.getElementById("loginPassword").value;
  const msg = document.getElementById("loginMsg");
  msg.textContent = "";

  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const data = await res.json();

  if (!res.ok) {
    msg.textContent = data.error;
    msg.className = "error";
    return;
  }

  if (data.trusted) {
    showOnly("pinSetupSection");
    return;
  }

  pendingEmail = email;
  showOnly("otpSection");
});

document.getElementById("verifyBtn").addEventListener("click", async () => {
  const code = document.getElementById("otp").value.trim();
  const msg = document.getElementById("otpMsg");
  msg.textContent = "";

  const res = await fetch("/api/verify-otp", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: pendingEmail, code }),
  });
  const data = await res.json();

  if (!res.ok) {
    msg.textContent = data.error;
    msg.className = "error";
    return;
  }

  showOnly("pinSetupSection");
});

document.getElementById("setPinBtn").addEventListener("click", async () => {
  const password = document.getElementById("confirmPassword").value;
  const pin = document.getElementById("newPin").value.trim();
  const msg = document.getElementById("pinSetupMsg");
  msg.textContent = "";

  const res = await fetch("/api/set-pin", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ password, pin }),
  });
  const data = await res.json();

  if (!res.ok) {
    msg.textContent = data.error;
    msg.className = "error";
    return;
  }

  msg.textContent = "PIN saved! Next time this device offers a fast PIN login.";
  msg.className = "success";
});
</script>
</body>
</html>`;