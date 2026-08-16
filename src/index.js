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
import { ringgitToSen, senToRinggit } from "./money.js";

const OTP_TTL_MS = 10 * 60 * 1000; // 10 minutes
const MAX_PIN_ATTEMPTS = 5;
const PIN_LOCKOUT_MS = 5 * 60 * 1000; // 5 minutes

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

      if (request.method === "GET" && url.pathname === "/api/device-status") {
        return handleDeviceStatus(request, env);
      }

      if (request.method === "GET" && url.pathname === "/api/staff-list") {
        return handleStaffList(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/pin-login") {
        return handlePinLogin(request, env);
      }

      if (request.method === "GET" && url.pathname === "/api/products") {
        return handleListProducts(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/products") {
        return handleCreateProduct(request, env);
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

async function handleDeviceStatus(request, env) {
  const cookies = parseCookies(request.headers.get("Cookie"));
  let trusted = false;
  if (cookies.device) {
    const trustedDevice = await env.DB.prepare(
      "SELECT id FROM trusted_devices WHERE device_token = ? AND is_active = 1"
    )
      .bind(cookies.device)
      .first();
    trusted = !!trustedDevice;
  }

  // Also tells the frontend whether an owner exists yet, so an untrusted
  // device shows the login form by default instead of always defaulting
  // to the one-time setup form.
  const owner = await env.DB.prepare("SELECT id FROM users WHERE role = 'owner' LIMIT 1").first();

  return jsonResponse({ trusted, owner_exists: !!owner });
}

async function handleStaffList(request, env) {
  const cookies = parseCookies(request.headers.get("Cookie"));
  const trustedDevice = cookies.device
    ? await env.DB.prepare("SELECT id FROM trusted_devices WHERE device_token = ? AND is_active = 1")
        .bind(cookies.device)
        .first()
    : null;

  if (!trustedDevice) {
    return jsonResponse({ error: "This device isn't trusted." }, 403);
  }

  // Only staff who have actually set a PIN show up here -- no point
  // offering a picker option that can't log in.
  const { results } = await env.DB.prepare(
    "SELECT id, name, role, pin_locked_until FROM users WHERE is_active = 1 AND pin_hash IS NOT NULL ORDER BY name"
  ).all();

  return jsonResponse({ staff: results });
}

async function handlePinLogin(request, env) {
  const { user_id, pin } = await request.json();

  if (!user_id || !pin) {
    return jsonResponse({ error: "Select your name and enter your PIN." }, 400);
  }

  // PIN login only works from a device that's already earned full trust.
  const cookies = parseCookies(request.headers.get("Cookie"));
  const trustedDevice = cookies.device
    ? await env.DB.prepare("SELECT id FROM trusted_devices WHERE device_token = ? AND is_active = 1")
        .bind(cookies.device)
        .first()
    : null;

  if (!trustedDevice) {
    return jsonResponse({ error: "This device isn't trusted. Log in with your password first." }, 403);
  }

  const user = await env.DB.prepare(
    "SELECT id, pin_hash, pin_failed_attempts, pin_locked_until, is_active FROM users WHERE id = ?"
  )
    .bind(user_id)
    .first();

  if (!user || !user.is_active || !user.pin_hash) {
    return jsonResponse({ error: "PIN login isn't available for this account." }, 400);
  }

  const now = new Date();

  if (user.pin_locked_until && new Date(user.pin_locked_until) > now) {
    return jsonResponse(
      {
        error: "Too many wrong attempts. Log in with your password instead.",
        locked_until: user.pin_locked_until,
      },
      423
    );
  }

  const validPin = await verifyPassword(pin, user.pin_hash);

  if (!validPin) {
    const attempts = user.pin_failed_attempts + 1;

    if (attempts >= MAX_PIN_ATTEMPTS) {
      const lockedUntil = new Date(now.getTime() + PIN_LOCKOUT_MS).toISOString();
      await env.DB.prepare("UPDATE users SET pin_failed_attempts = ?, pin_locked_until = ? WHERE id = ?")
        .bind(attempts, lockedUntil, user.id)
        .run();
      await env.DB.prepare(
        "INSERT INTO audit_log (user_id, action, entity_type, entity_id) VALUES (?, 'pin_locked', 'user', ?)"
      )
        .bind(user.id, user.id)
        .run();
      return jsonResponse(
        {
          error: "Too many wrong attempts. This PIN is now locked -- log in with your password instead.",
          locked_until: lockedUntil,
        },
        423
      );
    }

    await env.DB.prepare("UPDATE users SET pin_failed_attempts = ? WHERE id = ?")
      .bind(attempts, user.id)
      .run();
    return jsonResponse({ error: "Incorrect PIN." }, 400);
  }

  // Correct PIN -- clear any lockout state and log in.
  const nowIso = now.toISOString();
  await env.DB.prepare(
    "UPDATE users SET pin_failed_attempts = 0, pin_locked_until = NULL, last_login_at = ? WHERE id = ?"
  )
    .bind(nowIso, user.id)
    .run();

  await env.DB.prepare("UPDATE trusted_devices SET last_used_at = ? WHERE id = ?")
    .bind(nowIso, trustedDevice.id)
    .run();

  await env.DB.prepare(
    "INSERT INTO audit_log (user_id, action, entity_type, entity_id) VALUES (?, 'pin_login', 'user', ?)"
  )
    .bind(user.id, user.id)
    .run();

  const sessionToken = await createSessionToken(user.id, env.SESSION_SECRET);
  const headers = new Headers({ "content-type": "application/json" });
  headers.append(
    "Set-Cookie",
    `session=${sessionToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=43200`
  );
  return new Response(JSON.stringify({ success: true }), { headers });
}

async function handleListProducts(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }

  // No role restriction here -- cashiers need to see products to sell
  // them at checkout, same as everyone else.
  const { results } = await env.DB.prepare(
    `SELECT id, sku, name, item_type, unit_price, unit_of_measure, stock_quantity, reorder_level
     FROM products WHERE is_active = 1 ORDER BY name`
  ).all();

  const products = results.map((p) => ({ ...p, unit_price_display: senToRinggit(p.unit_price) }));
  return jsonResponse({ products });
}

async function handleCreateProduct(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  if (!["owner", "admin", "staff"].includes(currentUser.role)) {
    return jsonResponse({ error: "You don't have permission to manage products." }, 403);
  }

  const body = await request.json();
  const { name, item_type, unit_price, sku, stock_quantity } = body;

  if (!name || !item_type || unit_price === undefined || unit_price === null || unit_price === "") {
    return jsonResponse({ error: "Name, type, and price are required." }, 400);
  }
  if (!["goods", "service"].includes(item_type)) {
    return jsonResponse({ error: "Item type must be goods or service." }, 400);
  }

  const priceSen = ringgitToSen(unit_price);
  if (priceSen === null || priceSen < 0) {
    return jsonResponse({ error: "Enter a valid price." }, 400);
  }

  if (sku) {
    const existingSku = await env.DB.prepare("SELECT id FROM products WHERE sku = ?").bind(sku).first();
    if (existingSku) {
      return jsonResponse({ error: "That SKU is already used by another product." }, 400);
    }
  }

  // Stock tracking only applies to physical goods -- services stay NULL.
  const stockValue = item_type === "goods" ? Number(stock_quantity) || 0 : null;

  const result = await env.DB.prepare(
    `INSERT INTO products (sku, name, item_type, unit_price, stock_quantity)
     VALUES (?, ?, ?, ?, ?)`
  )
    .bind(sku || null, name, item_type, priceSen, stockValue)
    .run();

  await env.DB.prepare(
    "INSERT INTO audit_log (user_id, action, entity_type, entity_id) VALUES (?, 'product_created', 'product', ?)"
  )
    .bind(currentUser.id, result.meta.last_row_id)
    .run();

  return jsonResponse({ success: true, id: result.meta.last_row_id });
}

const HTML_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HarminPOS</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 600px; margin: 60px auto; padding: 0 20px; color: #1a1a1a; }
  h1 { font-size: 20px; margin-bottom: 4px; }
  p.sub { color: #666; margin-top: 0; margin-bottom: 24px; }
  label { display: block; margin-top: 16px; margin-bottom: 4px; font-size: 14px; font-weight: 600; }
  input { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 6px; font-size: 14px; box-sizing: border-box; }
  button { margin-top: 24px; width: 100%; padding: 12px; background: #1a1a1a; color: white; border: none; border-radius: 6px; font-size: 14px; cursor: pointer; }
  .error { color: #c0392b; margin-top: 12px; font-size: 14px; }
  .success { color: #27ae60; margin-top: 12px; font-size: 14px; }
  .lockWarning { background: #fff3cd; border: 1px solid #ffc107; color: #856404; padding: 10px 12px; border-radius: 6px; margin-top: 12px; font-size: 14px; }
  input:disabled, button:disabled { opacity: 0.5; cursor: not-allowed; }
  .toggle { margin-top: 16px; font-size: 13px; color: #666; text-align: center; }
  .toggle a { color: #1a1a1a; cursor: pointer; text-decoration: underline; }
  #setupSection, #loginSection, #otpSection, #pinSetupSection, #pinLoginSection, #dashboardSection { display: none; }
  .staffBtn { text-align: left; background: white; color: #1a1a1a; border: 1px solid #ccc; margin-top: 8px; }
  #pinPadSection { display: none; margin-top: 24px; padding-top: 24px; border-top: 1px solid #eee; }
  h2.sectionTitle { font-size: 15px; margin-top: 32px; margin-bottom: 4px; }
  .productRow { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #eee; font-size: 14px; }
  .productRow span:first-child { flex: 1; }
  .productRow span { color: #444; }
  select { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 6px; font-size: 14px; box-sizing: border-box; }
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

  <div id="pinLoginSection">
    <h1>Who's this?</h1>
    <p class="sub">Tap your name to log in.</p>
    <div id="staffList"></div>
    <div id="pinPadSection">
      <p class="sub" id="selectedStaffName"></p>
      <label for="pinInput">PIN</label>
      <input id="pinInput" type="password" maxlength="6" inputmode="numeric" />
      <button id="pinLoginBtn">Log in</button>
      <div id="pinLoginMsg"></div>
      <p class="toggle"><a id="backToStaffList">Not you? Choose again</a></p>
    </div>
    <p class="toggle"><a id="usePasswordInstead">Use password instead</a></p>
  </div>

  <div id="dashboardSection">
    <h1>HarminPOS</h1>
    <p class="sub" id="welcomeMsg"></p>

    <h2 class="sectionTitle">Products</h2>
    <div id="productList"></div>

    <div id="addProductSection">
      <h2 class="sectionTitle">Add a product</h2>
      <label for="prodName">Name</label>
      <input id="prodName" type="text" />
      <label for="prodType">Type</label>
      <select id="prodType">
        <option value="goods">Goods (physical item)</option>
        <option value="service">Service</option>
      </select>
      <label for="prodPrice">Price (RM)</label>
      <input id="prodPrice" type="number" step="0.01" min="0" />
      <label for="prodSku">SKU (optional)</label>
      <input id="prodSku" type="text" />
      <div id="stockFields">
        <label for="prodStock">Stock quantity</label>
        <input id="prodStock" type="number" min="0" />
      </div>
      <button id="addProductBtn">Add product</button>
      <div id="addProductMsg"></div>
    </div>
  </div>

<script>
let pendingEmail = "";
let selectedStaffId = null;
let countdownInterval = null;

// Ticks down a lockout countdown using the real server timestamp, so it
// shows the correct remaining time even after a page refresh -- refreshing
// re-fetches this timestamp from the database rather than resetting a
// client-side timer back to the full duration.
function showLockCountdown(lockedUntilIso) {
  const msg = document.getElementById("pinLoginMsg");
  const pinInput = document.getElementById("pinInput");
  const pinBtn = document.getElementById("pinLoginBtn");

  pinInput.disabled = true;
  pinBtn.disabled = true;
  msg.className = "lockWarning";

  if (countdownInterval) clearInterval(countdownInterval);

  function tick() {
    const remainingMs = new Date(lockedUntilIso) - new Date();
    if (remainingMs <= 0) {
      clearInterval(countdownInterval);
      countdownInterval = null;
      msg.textContent = "";
      msg.className = "";
      pinInput.disabled = false;
      pinBtn.disabled = false;
      return;
    }
    const totalSeconds = Math.ceil(remainingMs / 1000);
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    msg.textContent =
      "Too many wrong attempts. Try again in " + minutes + "m " + String(seconds).padStart(2, "0") + "s.";
  }

  tick();
  countdownInterval = setInterval(tick, 1000);
}

function showOnly(id) {
  ["setupSection", "loginSection", "otpSection", "pinSetupSection", "pinLoginSection", "dashboardSection"].forEach(
    (sectionId) => {
      document.getElementById(sectionId).style.display = sectionId === id ? "block" : "none";
    }
  );
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
    const me = await fetch("/api/me").then((r) => r.json());
    if (me.has_pin) {
      await loadDashboard();
    } else {
      showOnly("pinSetupSection");
    }
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

  const me = await fetch("/api/me").then((r) => r.json());
  if (me.has_pin) {
    await loadDashboard();
  } else {
    showOnly("pinSetupSection");
  }
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

  await loadDashboard();
});

async function checkDeviceStatus() {
  const res = await fetch("/api/device-status");
  const data = await res.json();

  if (data.trusted) {
    await loadStaffList();
    showOnly("pinLoginSection");
  } else if (data.owner_exists) {
    showOnly("loginSection");
  } else {
    showOnly("setupSection");
  }
}

async function loadStaffList() {
  const res = await fetch("/api/staff-list");
  const data = await res.json();
  const container = document.getElementById("staffList");
  container.innerHTML = "";

  (data.staff || []).forEach((person) => {
    const btn = document.createElement("button");
    btn.className = "staffBtn";
    btn.textContent = person.name;
    btn.addEventListener("click", () => {
      selectedStaffId = person.id;
      document.getElementById("selectedStaffName").textContent = "Logging in as " + person.name;
      document.getElementById("pinPadSection").style.display = "block";

      const pinInput = document.getElementById("pinInput");
      const msg = document.getElementById("pinLoginMsg");
      pinInput.value = "";
      msg.textContent = "";
      msg.className = ""; // clear any leftover warning styling from a previous selection
      if (countdownInterval) {
        clearInterval(countdownInterval);
        countdownInterval = null;
      }

      if (person.pin_locked_until && new Date(person.pin_locked_until) > new Date()) {
        showLockCountdown(person.pin_locked_until);
      } else {
        pinInput.disabled = false;
        document.getElementById("pinLoginBtn").disabled = false;
        pinInput.focus();
      }
    });
    container.appendChild(btn);
  });
}

document.getElementById("pinLoginBtn").addEventListener("click", async () => {
  const pin = document.getElementById("pinInput").value.trim();
  const msg = document.getElementById("pinLoginMsg");
  msg.textContent = "";

  const res = await fetch("/api/pin-login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ user_id: selectedStaffId, pin }),
  });
  const data = await res.json();

  if (!res.ok) {
    if (res.status === 423 && data.locked_until) {
      showLockCountdown(data.locked_until);
    } else {
      msg.textContent = data.error;
      msg.className = "error";
    }
    return;
  }

  await loadDashboard();
});

document.getElementById("backToStaffList").addEventListener("click", () => {
  document.getElementById("pinPadSection").style.display = "none";
  if (countdownInterval) {
    clearInterval(countdownInterval);
    countdownInterval = null;
  }
});

document.getElementById("usePasswordInstead").addEventListener("click", () => showOnly("loginSection"));

async function loadDashboard() {
  const me = await fetch("/api/me").then((r) => r.json());
  document.getElementById("welcomeMsg").textContent = "Logged in as " + me.name + " (" + me.role + ")";
  // Cashiers can see products at checkout later, but shouldn't see the
  // add-product form -- that's staff/admin/owner territory.
  document.getElementById("addProductSection").style.display = me.role === "cashier" ? "none" : "block";
  await loadProducts();
  showOnly("dashboardSection");
}

async function loadProducts() {
  const res = await fetch("/api/products");
  const data = await res.json();
  const container = document.getElementById("productList");
  container.innerHTML = "";

  if (!data.products || data.products.length === 0) {
    container.innerHTML = '<p class="sub">No products yet.</p>';
    return;
  }

  data.products.forEach((p) => {
    const row = document.createElement("div");
    row.className = "productRow";
    const stockText = p.item_type === "goods" ? "Stock: " + (p.stock_quantity ?? 0) : "Service";
    row.innerHTML =
      "<span>" + p.name + "</span><span>RM " + p.unit_price_display + "</span><span>" + stockText + "</span>";
    container.appendChild(row);
  });
}

document.getElementById("prodType").addEventListener("change", (e) => {
  document.getElementById("stockFields").style.display = e.target.value === "goods" ? "block" : "none";
});

document.getElementById("addProductBtn").addEventListener("click", async () => {
  const name = document.getElementById("prodName").value.trim();
  const item_type = document.getElementById("prodType").value;
  const unit_price = document.getElementById("prodPrice").value;
  const sku = document.getElementById("prodSku").value.trim();
  const stock_quantity = document.getElementById("prodStock").value;
  const msg = document.getElementById("addProductMsg");
  msg.textContent = "";

  const res = await fetch("/api/products", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      name,
      item_type,
      unit_price,
      sku: sku || undefined,
      stock_quantity: item_type === "goods" ? Number(stock_quantity || 0) : undefined,
    }),
  });
  const data = await res.json();

  if (!res.ok) {
    msg.textContent = data.error;
    msg.className = "error";
    return;
  }

  msg.textContent = "Product added!";
  msg.className = "success";
  document.getElementById("prodName").value = "";
  document.getElementById("prodPrice").value = "";
  document.getElementById("prodSku").value = "";
  document.getElementById("prodStock").value = "";
  await loadProducts();
});

checkDeviceStatus();
</script>
</body>
</html>`;