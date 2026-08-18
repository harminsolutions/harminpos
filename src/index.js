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

      if (request.method === "POST" && url.pathname === "/api/products/remove") {
        return handleRemoveProduct(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/products/edit") {
        return handleEditProduct(request, env);
      }

      if (request.method === "GET" && url.pathname === "/api/suppliers") {
        return handleListSuppliers(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/suppliers") {
        return handleCreateSupplier(request, env);
      }

      if (request.method === "GET" && url.pathname === "/api/users") {
        return handleListUsers(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/users") {
        return handleCreateUser(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/users/deactivate") {
        return handleDeactivateUser(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/users/reset-pin") {
        return handleResetPin(request, env);
      }

      if (request.method === "GET" && url.pathname === "/api/reports/employees") {
        return handleEmployeePerformance(request, env);
      }

      if (request.method === "GET" && url.pathname === "/api/sales") {
        return handleListSales(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/sales/void") {
        return handleVoidSale(request, env);
      }

      if (request.method === "GET" && url.pathname === "/api/business-profile") {
        return handleGetBusinessProfile(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/business-profile") {
        return handleSetBusinessProfile(request, env);
      }

      if (request.method === "GET" && url.pathname === "/api/audit-log") {
        return handleListAuditLog(request, env);
      }

      if (request.method === "GET" && url.pathname === "/api/devices") {
        return handleListDevices(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/devices/revoke") {
        return handleRevokeDevice(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/sales") {
        return handleCreateSale(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/shifts/open") {
        return handleOpenShift(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/shifts/close") {
        return handleCloseShift(request, env);
      }

      if (request.method === "GET" && url.pathname === "/api/shifts/current") {
        return handleCurrentShift(request, env);
      }

      if (request.method === "GET" && url.pathname === "/api/reports/summary") {
        return handleReportsSummary(request, env);
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
  const { name, email, password, business_type } = await request.json();

  if (!name || !email || !password) {
    return jsonResponse({ error: "Name, email, and password are required." }, 400);
  }
  if (password.length < 8) {
    return jsonResponse({ error: "Password must be at least 8 characters." }, 400);
  }
  const validTypes = ["retail", "food_beverage", "service", "other"];
  if (!business_type || !validTypes.includes(business_type)) {
    return jsonResponse({ error: "Select a business type." }, 400);
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

  // Business legal details (TIN, SSM number, etc.) get filled in later via
  // Settings -- this just plants the row early so business_type is captured
  // right at signup, with empty placeholders for the required fields.
  await env.DB.prepare(
    "INSERT INTO business_profile (id, legal_name, ssm_registration_no, tin, business_type) VALUES (1, '', '', '', ?)"
  )
    .bind(business_type)
    .run();

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
  const profile = await env.DB.prepare("SELECT business_type FROM business_profile WHERE id = 1").first();
  return jsonResponse({
    id: currentUser.id,
    name: currentUser.name,
    email: currentUser.email,
    role: currentUser.role,
    has_pin: !!currentUser.pin_hash,
    business_type: profile ? profile.business_type : null,
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
    `SELECT id, sku, name, item_type, unit_price, cost_price, unit_of_measure, stock_quantity, reorder_level, sst_applicable, sst_rate, supplier_id
     FROM products WHERE is_active = 1 ORDER BY name`
  ).all();

  const products = results.map((p) => ({
    ...p,
    unit_price_display: senToRinggit(p.unit_price),
    cost_price_display: p.cost_price !== null ? senToRinggit(p.cost_price) : "",
  }));
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
  const { name, item_type, unit_price, cost_price, sku, stock_quantity, sst_applicable, sst_rate, supplier_id } =
    body;

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

  const costSen = cost_price !== undefined && cost_price !== "" ? ringgitToSen(cost_price) : null;

  if (sku) {
    const existingSku = await env.DB.prepare("SELECT id FROM products WHERE sku = ?").bind(sku).first();
    if (existingSku) {
      return jsonResponse({ error: "That SKU is already used by another product." }, 400);
    }
  }

  // Stock tracking only applies to physical goods -- services stay NULL.
  const stockValue = item_type === "goods" ? Number(stock_quantity) || 0 : null;
  const sstApplicable = sst_applicable ? 1 : 0;
  const sstRateValue = sstApplicable ? Number(sst_rate) || 0 : null;

  const result = await env.DB.prepare(
    `INSERT INTO products (sku, name, item_type, unit_price, cost_price, stock_quantity, sst_applicable, sst_rate, supplier_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(sku || null, name, item_type, priceSen, costSen, stockValue, sstApplicable, sstRateValue, supplier_id || null)
    .run();

  await env.DB.prepare(
    "INSERT INTO audit_log (user_id, action, entity_type, entity_id) VALUES (?, 'product_created', 'product', ?)"
  )
    .bind(currentUser.id, result.meta.last_row_id)
    .run();

  return jsonResponse({ success: true, id: result.meta.last_row_id });
}

async function handleCreateSale(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }

  // A sale has to belong to a shift -- otherwise cash reconciliation at
  // shift close can't account for it.
  const openShift = await env.DB.prepare("SELECT id FROM cash_shifts WHERE cashier_id = ? AND status = 'open'")
    .bind(currentUser.id)
    .first();
  if (!openShift) {
    return jsonResponse({ error: "Open a shift before making sales." }, 400);
  }

  const body = await request.json();
  const { items, payment_method, customer_id, discount_amount } = body;

  if (!Array.isArray(items) || items.length === 0) {
    return jsonResponse({ error: "Cart is empty." }, 400);
  }
  if (!["cash", "duitnow_qr", "card", "other"].includes(payment_method)) {
    return jsonResponse({ error: "Select a valid payment method." }, 400);
  }

  const discountSen = discount_amount ? ringgitToSen(discount_amount) : 0;
  if (discountSen === null || discountSen < 0) {
    return jsonResponse({ error: "Enter a valid discount amount." }, 400);
  }

  // Load and validate every product BEFORE writing anything, so a bad item
  // partway through the cart doesn't leave a half-completed sale behind.
  const lineItems = [];
  let subtotal = 0;
  let sstAmount = 0;

  for (const item of items) {
    const qty = Number(item.quantity);
    if (!item.product_id || !qty || qty <= 0) {
      return jsonResponse({ error: "Invalid item in cart." }, 400);
    }

    const product = await env.DB.prepare(
      `SELECT id, name, item_type, unit_price, cost_price, sst_applicable, sst_rate, stock_quantity, is_active
       FROM products WHERE id = ?`
    )
      .bind(item.product_id)
      .first();

    if (!product || !product.is_active) {
      return jsonResponse({ error: "A product in your cart is no longer available." }, 400);
    }

    if (product.item_type === "goods" && (product.stock_quantity === null || product.stock_quantity < qty)) {
      return jsonResponse({ error: `Not enough stock for ${product.name}.` }, 400);
    }

    const lineSubtotal = product.unit_price * qty;
    const lineSst = product.sst_applicable ? Math.round(lineSubtotal * (product.sst_rate || 0)) : 0;

    subtotal += lineSubtotal;
    sstAmount += lineSst;

    lineItems.push({
      product_id: product.id,
      name: product.name,
      quantity: qty,
      unit_price: product.unit_price,
      cost_price: product.cost_price,
      sst_rate: product.sst_applicable ? product.sst_rate : null,
      line_total: lineSubtotal + lineSst,
      is_goods: product.item_type === "goods",
    });
  }

  const totalAmount = subtotal + sstAmount - discountSen;
  if (totalAmount < 0) {
    return jsonResponse({ error: "Discount can't be more than the order total." }, 400);
  }

  // Sequential, human-readable receipt number -- e.g. INV-000001.
  const countRow = await env.DB.prepare("SELECT COUNT(*) as count FROM sales").first();
  const receiptNumber = "INV-" + String(countRow.count + 1).padStart(6, "0");
  const now = new Date().toISOString();

  // No live payment gateway wired up yet, so every method is recorded as
  // completed immediately -- swapping in real DuitNow QR/card confirmation
  // later just changes this one line, not the rest of the checkout flow.
  const saleResult = await env.DB.prepare(
    `INSERT INTO sales (receipt_number, cashier_id, shift_id, customer_id, subtotal, sst_amount, discount_amount, total_amount, payment_method, payment_status, einvoice_status, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', 'not_required', ?)`
  )
    .bind(
      receiptNumber,
      currentUser.id,
      openShift.id,
      customer_id || null,
      subtotal,
      sstAmount,
      discountSen,
      totalAmount,
      payment_method,
      now
    )
    .run();

  const saleId = saleResult.meta.last_row_id;

  for (const li of lineItems) {
    await env.DB.prepare(
      `INSERT INTO sale_items (sale_id, product_id, product_name_snapshot, quantity, unit_price_snapshot, sst_rate_snapshot, cost_price_snapshot, line_total)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(saleId, li.product_id, li.name, li.quantity, li.unit_price, li.sst_rate, li.cost_price, li.line_total)
      .run();

    if (li.is_goods) {
      await env.DB.prepare("UPDATE products SET stock_quantity = stock_quantity - ? WHERE id = ?")
        .bind(li.quantity, li.product_id)
        .run();
    }
  }

  await env.DB.prepare(
    "INSERT INTO audit_log (user_id, action, entity_type, entity_id) VALUES (?, 'sale_created', 'sale', ?)"
  )
    .bind(currentUser.id, saleId)
    .run();

  return jsonResponse({
    success: true,
    sale: {
      id: saleId,
      receipt_number: receiptNumber,
      subtotal: senToRinggit(subtotal),
      sst_amount: senToRinggit(sstAmount),
      discount_amount: senToRinggit(discountSen),
      total_amount: senToRinggit(totalAmount),
      payment_method,
      items: lineItems.map((li) => ({
        name: li.name,
        quantity: li.quantity,
        unit_price: senToRinggit(li.unit_price),
        line_total: senToRinggit(li.line_total),
      })),
    },
  });
}

async function handleOpenShift(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }

  const existingOpen = await env.DB.prepare("SELECT id FROM cash_shifts WHERE cashier_id = ? AND status = 'open'")
    .bind(currentUser.id)
    .first();
  if (existingOpen) {
    return jsonResponse({ error: "You already have an open shift." }, 400);
  }

  const body = await request.json();
  const openingCashSen = ringgitToSen(body.opening_cash);
  if (openingCashSen === null || openingCashSen < 0) {
    return jsonResponse({ error: "Enter a valid starting cash amount." }, 400);
  }

  // Set opened_at explicitly rather than relying on the schema's default --
  // keeps every timestamp in this app in the same ISO format, since
  // SQLite's own CURRENT_TIMESTAMP uses a different format that browsers
  // don't always parse consistently.
  const now = new Date().toISOString();

  const result = await env.DB.prepare(
    "INSERT INTO cash_shifts (cashier_id, opening_cash, status, opened_at) VALUES (?, ?, 'open', ?)"
  )
    .bind(currentUser.id, openingCashSen, now)
    .run();

  await env.DB.prepare(
    "INSERT INTO audit_log (user_id, action, entity_type, entity_id) VALUES (?, 'shift_opened', 'cash_shift', ?)"
  )
    .bind(currentUser.id, result.meta.last_row_id)
    .run();

  return jsonResponse({ success: true, shift_id: result.meta.last_row_id });
}

async function handleCloseShift(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }

  const shift = await env.DB.prepare(
    "SELECT id, opening_cash FROM cash_shifts WHERE cashier_id = ? AND status = 'open'"
  )
    .bind(currentUser.id)
    .first();
  if (!shift) {
    return jsonResponse({ error: "You don't have an open shift." }, 400);
  }

  const body = await request.json();
  const actualCashSen = ringgitToSen(body.closing_cash_actual);
  if (actualCashSen === null || actualCashSen < 0) {
    return jsonResponse({ error: "Enter a valid counted cash amount." }, 400);
  }

  // Expected cash = starting float + every cash sale recorded during this
  // shift. Card/QR sales don't affect the physical till, so they're
  // excluded from this check entirely.
  const cashSalesRow = await env.DB.prepare(
    "SELECT COALESCE(SUM(total_amount), 0) as total FROM sales WHERE shift_id = ? AND payment_method = 'cash' AND is_voided = 0"
  )
    .bind(shift.id)
    .first();

  const expected = shift.opening_cash + cashSalesRow.total;
  const discrepancy = actualCashSen - expected;
  const now = new Date().toISOString();

  await env.DB.prepare(
    `UPDATE cash_shifts SET status = 'closed', closing_cash_expected = ?, closing_cash_actual = ?, discrepancy = ?, closed_at = ?
     WHERE id = ?`
  )
    .bind(expected, actualCashSen, discrepancy, now, shift.id)
    .run();

  await env.DB.prepare(
    "INSERT INTO audit_log (user_id, action, entity_type, entity_id) VALUES (?, 'shift_closed', 'cash_shift', ?)"
  )
    .bind(currentUser.id, shift.id)
    .run();

  return jsonResponse({
    success: true,
    expected: senToRinggit(expected),
    actual: senToRinggit(actualCashSen),
    discrepancy: senToRinggit(discrepancy),
  });
}

async function handleCurrentShift(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }

  const shift = await env.DB.prepare(
    "SELECT id, opening_cash FROM cash_shifts WHERE cashier_id = ? AND status = 'open'"
  )
    .bind(currentUser.id)
    .first();

  if (!shift) {
    return jsonResponse({ open: false });
  }

  return jsonResponse({ open: true, shift_id: shift.id, opening_cash: senToRinggit(shift.opening_cash) });
}

// Shared by reports and employee performance -- "today" resets at UTC
// midnight, which can run up to 8 hours behind Malaysia time, while
// "week"/"month" are simple rolling windows rather than exact calendar
// boundaries. Good enough for a first version of range reporting.
function getRangeStart(range) {
  const now = new Date();
  if (range === "week") {
    return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
  }
  if (range === "month") {
    return new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
  }
  const todayStart = new Date(now);
  todayStart.setUTCHours(0, 0, 0, 0);
  return todayStart.toISOString();
}

async function handleReportsSummary(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  if (!["owner", "admin", "staff"].includes(currentUser.role)) {
    return jsonResponse({ error: "You don't have permission to view reports." }, 403);
  }

  const url = new URL(request.url);
  const range = url.searchParams.get("range") || "today";
  const startIso = getRangeStart(range);

  const salesRow = await env.DB.prepare(
    "SELECT COUNT(*) as sale_count, COALESCE(SUM(total_amount), 0) as revenue FROM sales WHERE is_voided = 0 AND created_at >= ?"
  )
    .bind(startIso)
    .first();

  const profitRow = await env.DB.prepare(
    `SELECT COALESCE(SUM((si.unit_price_snapshot - COALESCE(si.cost_price_snapshot, 0)) * si.quantity), 0) as profit
     FROM sale_items si
     JOIN sales s ON s.id = si.sale_id
     WHERE s.is_voided = 0 AND s.created_at >= ?`
  )
    .bind(startIso)
    .first();

  return jsonResponse({
    range,
    sale_count: salesRow.sale_count,
    revenue: senToRinggit(salesRow.revenue),
    profit: senToRinggit(profitRow.profit),
  });
}

async function handleEmployeePerformance(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  if (!["owner", "admin"].includes(currentUser.role)) {
    return jsonResponse({ error: "You don't have permission to view this." }, 403);
  }

  const url = new URL(request.url);
  const range = url.searchParams.get("range") || "today";
  const startIso = getRangeStart(range);

  const { results } = await env.DB.prepare(
    `SELECT u.name,
            SUM(CASE WHEN s.is_voided = 0 THEN 1 ELSE 0 END) as sale_count,
            COALESCE(SUM(CASE WHEN s.is_voided = 0 THEN s.total_amount ELSE 0 END), 0) as revenue,
            SUM(CASE WHEN s.is_voided = 1 THEN 1 ELSE 0 END) as void_count
     FROM sales s JOIN users u ON u.id = s.cashier_id
     WHERE s.created_at >= ?
     GROUP BY s.cashier_id
     ORDER BY revenue DESC`
  )
    .bind(startIso)
    .all();

  const performance = results.map((r) => ({ ...r, revenue_display: senToRinggit(r.revenue) }));
  return jsonResponse({ performance });
}

async function handleRemoveProduct(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  if (!["owner", "admin", "staff"].includes(currentUser.role)) {
    return jsonResponse({ error: "You don't have permission to manage products." }, 403);
  }

  const { product_id } = await request.json();
  if (!product_id) {
    return jsonResponse({ error: "Missing product." }, 400);
  }

  const product = await env.DB.prepare("SELECT id FROM products WHERE id = ?").bind(product_id).first();
  if (!product) {
    return jsonResponse({ error: "Product not found." }, 404);
  }

  // Soft delete -- keeps every past sale's line items pointing at a real
  // row, since sale_items references product_id and history must stay
  // intact even after a product is discontinued.
  await env.DB.prepare("UPDATE products SET is_active = 0 WHERE id = ?").bind(product_id).run();

  await env.DB.prepare(
    "INSERT INTO audit_log (user_id, action, entity_type, entity_id) VALUES (?, 'product_removed', 'product', ?)"
  )
    .bind(currentUser.id, product_id)
    .run();

  return jsonResponse({ success: true });
}

async function handleEditProduct(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  if (!["owner", "admin", "staff"].includes(currentUser.role)) {
    return jsonResponse({ error: "You don't have permission to manage products." }, 403);
  }

  const body = await request.json();
  const { product_id, name, item_type, unit_price, cost_price, sku, stock_quantity, sst_applicable, sst_rate, supplier_id } =
    body;

  if (!product_id) {
    return jsonResponse({ error: "Missing product." }, 400);
  }

  const existing = await env.DB.prepare("SELECT id FROM products WHERE id = ?").bind(product_id).first();
  if (!existing) {
    return jsonResponse({ error: "Product not found." }, 404);
  }

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
  const costSen = cost_price !== undefined && cost_price !== "" ? ringgitToSen(cost_price) : null;

  if (sku) {
    const skuClash = await env.DB.prepare("SELECT id FROM products WHERE sku = ? AND id != ?")
      .bind(sku, product_id)
      .first();
    if (skuClash) {
      return jsonResponse({ error: "That SKU is already used by another product." }, 400);
    }
  }

  const stockValue = item_type === "goods" ? Number(stock_quantity) || 0 : null;
  const sstApplicable = sst_applicable ? 1 : 0;
  const sstRateValue = sstApplicable ? Number(sst_rate) || 0 : null;

  await env.DB.prepare(
    `UPDATE products SET name=?, item_type=?, unit_price=?, cost_price=?, sku=?, stock_quantity=?, sst_applicable=?, sst_rate=?, supplier_id=?, updated_at=?
     WHERE id = ?`
  )
    .bind(
      name,
      item_type,
      priceSen,
      costSen,
      sku || null,
      stockValue,
      sstApplicable,
      sstRateValue,
      supplier_id || null,
      new Date().toISOString(),
      product_id
    )
    .run();

  await env.DB.prepare(
    "INSERT INTO audit_log (user_id, action, entity_type, entity_id) VALUES (?, 'product_edited', 'product', ?)"
  )
    .bind(currentUser.id, product_id)
    .run();

  return jsonResponse({ success: true });
}

async function handleListSuppliers(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  if (!["owner", "admin", "staff"].includes(currentUser.role)) {
    return jsonResponse({ error: "You don't have permission to view suppliers." }, 403);
  }

  const { results } = await env.DB.prepare(
    "SELECT id, name, contact_person, phone, email FROM suppliers WHERE is_active = 1 ORDER BY name"
  ).all();

  return jsonResponse({ suppliers: results });
}

async function handleCreateSupplier(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  if (!["owner", "admin", "staff"].includes(currentUser.role)) {
    return jsonResponse({ error: "You don't have permission to manage suppliers." }, 403);
  }

  const { name, contact_person, phone, email, address } = await request.json();
  if (!name) {
    return jsonResponse({ error: "Supplier name is required." }, 400);
  }

  const result = await env.DB.prepare(
    "INSERT INTO suppliers (name, contact_person, phone, email, address) VALUES (?, ?, ?, ?, ?)"
  )
    .bind(name, contact_person || null, phone || null, email || null, address || null)
    .run();

  await env.DB.prepare(
    "INSERT INTO audit_log (user_id, action, entity_type, entity_id) VALUES (?, 'supplier_created', 'supplier', ?)"
  )
    .bind(currentUser.id, result.meta.last_row_id)
    .run();

  return jsonResponse({ success: true, id: result.meta.last_row_id });
}

async function handleListUsers(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  if (!["owner", "admin"].includes(currentUser.role)) {
    return jsonResponse({ error: "You don't have permission to view staff." }, 403);
  }

  const { results } = await env.DB.prepare(
    "SELECT id, name, email, role FROM users WHERE is_active = 1 ORDER BY role, name"
  ).all();

  return jsonResponse({ users: results });
}

async function handleCreateUser(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  if (!["owner", "admin"].includes(currentUser.role)) {
    return jsonResponse({ error: "You don't have permission to add accounts." }, 403);
  }

  const { name, email, role, password } = await request.json();

  if (!name || !email || !role || !password) {
    return jsonResponse({ error: "Name, email, role, and password are required." }, 400);
  }
  if (!["admin", "staff", "cashier"].includes(role)) {
    return jsonResponse({ error: "Invalid role." }, 400);
  }
  if (password.length < 8) {
    return jsonResponse({ error: "Password must be at least 8 characters." }, 400);
  }

  // Only the owner can create another admin account -- admins can bring on
  // staff and cashiers, but can't promote anyone into their own tier.
  if (role === "admin" && currentUser.role !== "owner") {
    return jsonResponse({ error: "Only the owner can add admin accounts." }, 403);
  }

  const existingEmail = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
  if (existingEmail) {
    return jsonResponse({ error: "That email is already registered." }, 400);
  }

  const passwordHash = await hashPassword(password);

  const result = await env.DB.prepare("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)")
    .bind(name, email, passwordHash, role)
    .run();

  await env.DB.prepare(
    "INSERT INTO audit_log (user_id, action, entity_type, entity_id) VALUES (?, 'user_created', 'user', ?)"
  )
    .bind(currentUser.id, result.meta.last_row_id)
    .run();

  return jsonResponse({ success: true, id: result.meta.last_row_id });
}

async function handleDeactivateUser(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  if (!["owner", "admin"].includes(currentUser.role)) {
    return jsonResponse({ error: "You don't have permission to manage staff." }, 403);
  }

  const { user_id } = await request.json();
  if (!user_id) {
    return jsonResponse({ error: "Missing account." }, 400);
  }
  if (Number(user_id) === currentUser.id) {
    return jsonResponse({ error: "You can't deactivate your own account." }, 400);
  }

  const target = await env.DB.prepare("SELECT id, role FROM users WHERE id = ?").bind(user_id).first();
  if (!target) {
    return jsonResponse({ error: "Account not found." }, 404);
  }
  if (target.role === "owner") {
    return jsonResponse({ error: "The owner account can't be deactivated." }, 400);
  }
  if (target.role === "admin" && currentUser.role !== "owner") {
    return jsonResponse({ error: "Only the owner can deactivate an admin." }, 403);
  }

  await env.DB.prepare("UPDATE users SET is_active = 0 WHERE id = ?").bind(user_id).run();

  await env.DB.prepare(
    "INSERT INTO audit_log (user_id, action, entity_type, entity_id) VALUES (?, 'user_deactivated', 'user', ?)"
  )
    .bind(currentUser.id, user_id)
    .run();

  return jsonResponse({ success: true });
}

async function handleResetPin(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  if (!["owner", "admin"].includes(currentUser.role)) {
    return jsonResponse({ error: "You don't have permission to manage staff." }, 403);
  }

  const { user_id } = await request.json();
  if (!user_id) {
    return jsonResponse({ error: "Missing account." }, 400);
  }
  if (Number(user_id) === currentUser.id) {
    return jsonResponse({ error: "Use Set your PIN to change your own PIN." }, 400);
  }

  const target = await env.DB.prepare("SELECT id, role FROM users WHERE id = ?").bind(user_id).first();
  if (!target) {
    return jsonResponse({ error: "Account not found." }, 404);
  }
  if (target.role === "owner") {
    return jsonResponse({ error: "The owner's PIN can't be reset this way." }, 400);
  }
  if (target.role === "admin" && currentUser.role !== "owner") {
    return jsonResponse({ error: "Only the owner can reset an admin's PIN." }, 403);
  }

  // Clear the PIN entirely rather than setting a new one -- the owner/admin
  // never learns anyone else's PIN this way. The person just re-authenticates
  // with their password next time and sets a fresh PIN themselves.
  await env.DB.prepare(
    "UPDATE users SET pin_hash = NULL, pin_failed_attempts = 0, pin_locked_until = NULL WHERE id = ?"
  )
    .bind(user_id)
    .run();

  await env.DB.prepare(
    "INSERT INTO audit_log (user_id, action, entity_type, entity_id) VALUES (?, 'pin_reset', 'user', ?)"
  )
    .bind(currentUser.id, user_id)
    .run();

  return jsonResponse({ success: true });
}

async function handleListSales(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  if (!["owner", "admin", "staff"].includes(currentUser.role)) {
    return jsonResponse({ error: "You don't have permission to view sales." }, 403);
  }

  const { results } = await env.DB.prepare(
    `SELECT s.id, s.receipt_number, s.total_amount, s.payment_method, s.is_voided, s.created_at, u.name as cashier_name
     FROM sales s JOIN users u ON u.id = s.cashier_id
     ORDER BY s.created_at DESC LIMIT 50`
  ).all();

  const sales = results.map((s) => ({ ...s, total_display: senToRinggit(s.total_amount) }));
  return jsonResponse({ sales });
}

async function handleVoidSale(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  if (!["owner", "admin"].includes(currentUser.role)) {
    return jsonResponse({ error: "Only an owner or admin can void a sale." }, 403);
  }

  const { sale_id, reason } = await request.json();
  if (!sale_id) {
    return jsonResponse({ error: "Missing sale." }, 400);
  }

  const sale = await env.DB.prepare("SELECT id, is_voided FROM sales WHERE id = ?").bind(sale_id).first();
  if (!sale) {
    return jsonResponse({ error: "Sale not found." }, 404);
  }
  if (sale.is_voided) {
    return jsonResponse({ error: "This sale is already voided." }, 400);
  }

  // Reverse the stock deduction for any physical goods in this sale --
  // voiding a sale means it never really happened, so the stock shouldn't
  // stay down either.
  const { results: items } = await env.DB.prepare("SELECT product_id, quantity FROM sale_items WHERE sale_id = ?")
    .bind(sale_id)
    .all();

  for (const item of items) {
    if (!item.product_id) continue;
    await env.DB.prepare("UPDATE products SET stock_quantity = stock_quantity + ? WHERE id = ? AND item_type = 'goods'")
      .bind(item.quantity, item.product_id)
      .run();
  }

  await env.DB.prepare("UPDATE sales SET is_voided = 1, voided_by = ?, voided_reason = ? WHERE id = ?")
    .bind(currentUser.id, reason || null, sale_id)
    .run();

  await env.DB.prepare(
    "INSERT INTO audit_log (user_id, action, entity_type, entity_id, details) VALUES (?, 'sale_voided', 'sale', ?, ?)"
  )
    .bind(currentUser.id, sale_id, reason || null)
    .run();

  return jsonResponse({ success: true });
}

async function handleGetBusinessProfile(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  if (!["owner", "admin"].includes(currentUser.role)) {
    return jsonResponse({ error: "You don't have permission to view business details." }, 403);
  }

  const profile = await env.DB.prepare("SELECT * FROM business_profile WHERE id = 1").first();
  return jsonResponse({ profile: profile || null });
}

async function handleSetBusinessProfile(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  // Editing legal/tax details is owner-only -- these feed e-Invoice
  // submissions directly, so a mistake here is a compliance problem,
  // not just a typo.
  if (currentUser.role !== "owner") {
    return jsonResponse({ error: "Only the owner can edit business details." }, 403);
  }

  const body = await request.json();
  const {
    legal_name,
    trading_name,
    ssm_registration_no,
    tin,
    sst_registration_no,
    msic_code,
    address_line1,
    address_line2,
    city,
    state,
    postcode,
    phone,
    email,
  } = body;

  if (!legal_name || !ssm_registration_no || !tin) {
    return jsonResponse({ error: "Legal name, SSM registration number, and TIN are required." }, 400);
  }

  const now = new Date().toISOString();
  const existing = await env.DB.prepare("SELECT id FROM business_profile WHERE id = 1").first();

  if (existing) {
    await env.DB.prepare(
      `UPDATE business_profile SET legal_name=?, trading_name=?, ssm_registration_no=?, tin=?, sst_registration_no=?, msic_code=?,
       address_line1=?, address_line2=?, city=?, state=?, postcode=?, phone=?, email=?, updated_at=? WHERE id = 1`
    )
      .bind(
        legal_name,
        trading_name || null,
        ssm_registration_no,
        tin,
        sst_registration_no || null,
        msic_code || null,
        address_line1 || null,
        address_line2 || null,
        city || null,
        state || null,
        postcode || null,
        phone || null,
        email || null,
        now
      )
      .run();
  } else {
    await env.DB.prepare(
      `INSERT INTO business_profile (id, legal_name, trading_name, ssm_registration_no, tin, sst_registration_no, msic_code, address_line1, address_line2, city, state, postcode, phone, email)
       VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        legal_name,
        trading_name || null,
        ssm_registration_no,
        tin,
        sst_registration_no || null,
        msic_code || null,
        address_line1 || null,
        address_line2 || null,
        city || null,
        state || null,
        postcode || null,
        phone || null,
        email || null
      )
      .run();
  }

  await env.DB.prepare(
    "INSERT INTO audit_log (user_id, action, entity_type, entity_id) VALUES (?, 'business_profile_updated', 'business_profile', 1)"
  )
    .bind(currentUser.id)
    .run();

  return jsonResponse({ success: true });
}

async function handleListAuditLog(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  if (!["owner", "admin"].includes(currentUser.role)) {
    return jsonResponse({ error: "You don't have permission to view the audit log." }, 403);
  }

  const { results } = await env.DB.prepare(
    `SELECT a.id, a.action, a.entity_type, a.entity_id, a.created_at, u.name as user_name
     FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
     ORDER BY a.created_at DESC LIMIT 100`
  ).all();

  return jsonResponse({ logs: results });
}

async function handleListDevices(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  if (!["owner", "admin"].includes(currentUser.role)) {
    return jsonResponse({ error: "You don't have permission to view devices." }, 403);
  }

  const { results } = await env.DB.prepare(
    `SELECT d.id, d.device_name, d.trusted_at, d.last_used_at, d.is_active, u.name as verified_by_name
     FROM trusted_devices d JOIN users u ON u.id = d.verified_by
     ORDER BY d.trusted_at DESC`
  ).all();

  return jsonResponse({ devices: results });
}

async function handleRevokeDevice(request, env) {
  const currentUser = await getCurrentUser(request, env);
  if (!currentUser) {
    return jsonResponse({ error: "Not logged in." }, 401);
  }
  if (!["owner", "admin"].includes(currentUser.role)) {
    return jsonResponse({ error: "You don't have permission to manage devices." }, 403);
  }

  const { device_id } = await request.json();
  if (!device_id) {
    return jsonResponse({ error: "Missing device." }, 400);
  }

  await env.DB.prepare("UPDATE trusted_devices SET is_active = 0 WHERE id = ?").bind(device_id).run();

  await env.DB.prepare(
    "INSERT INTO audit_log (user_id, action, entity_type, entity_id) VALUES (?, 'device_revoked', 'trusted_device', ?)"
  )
    .bind(currentUser.id, device_id)
    .run();

  return jsonResponse({ success: true });
}

const HTML_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HarminPOS</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,500;9..144,600;9..144,700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --ink: #101B2D;
    --ink-soft: #1E3350;
    --paper: #FBF9F5;
    --paper-edge: #E4DFD3;
    --brass: #A87C2E;
    --brass-bright: #C99A42;
    --text: #16202E;
    --text-muted: #6B7686;
    --success: #3F7A54;
    --danger: #B5432E;
  }
  * { box-sizing: border-box; }
  body { font-family: 'Inter', system-ui, sans-serif; margin: 0; background: var(--paper); color: var(--text); }
  h1 { font-family: 'Fraunces', serif; font-size: 22px; font-weight: 600; margin-bottom: 4px; letter-spacing: -0.01em; }
  h2.sectionTitle { font-family: 'Fraunces', serif; font-size: 17px; font-weight: 600; color: var(--ink); margin-top: 32px; margin-bottom: 10px; }
  p.sub { color: var(--text-muted); margin-top: 0; margin-bottom: 24px; font-size: 14px; }
  label { display: block; margin-top: 16px; margin-bottom: 4px; font-size: 13px; font-weight: 600; color: var(--text); }
  input, select { width: 100%; padding: 11px 12px; border: 1px solid var(--paper-edge); border-radius: 8px; font-size: 14px; box-sizing: border-box; font-family: 'Inter', sans-serif; background: white; color: var(--text); }
  input:focus, select:focus { outline: none; border-color: var(--brass); box-shadow: 0 0 0 3px rgba(168,124,46,0.12); }
  input[type="checkbox"] { width: auto; }
  button { margin-top: 24px; width: 100%; padding: 13px; background: var(--ink); color: white; border: none; border-radius: 8px; font-size: 14px; font-weight: 600; font-family: 'Inter', sans-serif; cursor: pointer; transition: background 0.15s ease; }
  button:hover { background: var(--ink-soft); }
  input:disabled, button:disabled { opacity: 0.5; cursor: not-allowed; }
  .error { color: var(--danger); margin-top: 12px; font-size: 14px; }
  .success { color: var(--success); margin-top: 12px; font-size: 14px; }
  .lockWarning { background: #FBF0DD; border: 1px solid var(--brass); color: #7A5A1E; padding: 10px 12px; border-radius: 8px; margin-top: 12px; font-size: 14px; }
  .toggle { margin-top: 16px; font-size: 13px; color: var(--text-muted); text-align: center; }
  .toggle a { color: var(--ink); cursor: pointer; text-decoration: underline; }
  .inlineLabel { display: flex; align-items: center; gap: 8px; margin-top: 16px; font-size: 14px; font-weight: 600; }
  .bizTypeGrid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 8px; }
  .bizTypeBtn { display: flex; flex-direction: column; align-items: flex-start; gap: 4px; text-align: left; background: white; color: var(--text); border: 2px solid var(--paper-edge); margin: 0; padding: 14px; font-weight: 400; }
  .bizTypeBtn:hover { background: var(--paper); }
  .bizTypeBtn.selected { border-color: var(--brass); background: #FBF3E7; }
  .bizTypeName { font-weight: 600; font-size: 14px; color: var(--text); }
  .bizTypeDesc { font-size: 12px; color: var(--text-muted); }
  @media (max-width: 480px) {
    .bizTypeGrid { grid-template-columns: 1fr; }
  }
  .smallBtn { width: auto; margin: 0 0 0 12px; padding: 6px 14px; font-size: 13px; background: white; color: var(--ink); border: 1px solid var(--paper-edge); }
  .smallBtn:hover { background: var(--paper); }
  .staffBtn { text-align: left; background: white; color: var(--text); border: 1px solid var(--paper-edge); margin-top: 8px; font-weight: 500; }
  .productRow { display: flex; justify-content: space-between; gap: 16px; padding: 10px 0; border-bottom: 1px solid var(--paper-edge); font-size: 14px; }
  .productRow span:first-child { flex: 1; }
  .productRow span { color: var(--text); }
  .lowStock { color: var(--danger) !important; font-weight: 600; }
  .totalRow { font-weight: 700; }

  /* Auth screens keep a narrow, centered card feel */
  #setupSection, #loginSection, #otpSection, #pinSetupSection, #pinLoginSection {
    display: none; max-width: 420px; margin: 60px auto; padding: 0 24px;
  }
  #pinPadSection { display: none; margin-top: 24px; padding-top: 24px; border-top: 1px solid var(--paper-edge); }

  /* Dashboard shell */
  #dashboardSection { display: none; }
  .topBar { background: var(--ink); color: white; padding: 16px 28px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; }
  .brand-mark { font-family: 'Fraunces', serif; font-weight: 600; font-size: 20px; letter-spacing: -0.01em; }
  .topBarUser { font-size: 13px; color: #A7B3C4; }
  .tabBar { background: white; border-bottom: 1px solid var(--paper-edge); padding: 0 28px; display: flex; gap: 4px; overflow-x: auto; }
  .tabBtn { width: auto; background: none; color: var(--text-muted); border: none; border-bottom: 2px solid transparent; border-radius: 0; padding: 14px 4px; margin: 0 20px 0 0; font-weight: 600; font-size: 14px; white-space: nowrap; }
  .tabBtn:hover { background: none; color: var(--ink); }
  .tabBtn.active { color: var(--ink); border-bottom-color: var(--brass); }
  #productsTab, #suppliersTab, #reportsTab, #staffTab, #settingsTab { display: none; }
  .padded-panel { max-width: 880px; margin: 0 auto; padding: 28px; }

  /* Checkout: two-column POS layout */
  #checkoutTab { display: none; }
  .pos-layout { display: grid; grid-template-columns: 1fr 400px; align-items: start; }
  .pos-left { padding: 24px 28px; }
  .pos-right { background: white; border-left: 1px solid var(--paper-edge); padding: 24px; min-height: calc(100vh - 113px); display: flex; flex-direction: column; position: sticky; top: 0; }
  #shiftClosedView, #shiftOpenView { background: white; border: 1px solid var(--paper-edge); border-radius: 10px; padding: 16px 18px; margin-bottom: 20px; }
  #shiftClosedView button, #shiftOpenView button { margin-top: 12px; }
  #posSearch { margin-bottom: 18px; }
  .product-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 12px; }
  .product-card { background: white; border: 1px solid var(--paper-edge); border-radius: 10px; padding: 16px 14px; cursor: pointer; transition: transform 0.12s ease, box-shadow 0.12s ease, border-color 0.12s ease; text-align: left; width: 100%; margin: 0; }
  .product-card:hover { border-color: var(--brass); box-shadow: 0 4px 14px rgba(16,27,45,0.10); transform: translateY(-2px); background: white; }
  .product-card .p-name { font-weight: 600; font-size: 14px; color: var(--text); margin-bottom: 8px; line-height: 1.3; }
  .product-card .p-price { font-family: 'Fraunces', serif; font-size: 18px; font-weight: 600; color: var(--brass); }
  .product-card .p-meta { font-size: 11px; color: var(--text-muted); margin-top: 6px; }
  .order-header { font-family: 'Fraunces', serif; font-size: 18px; font-weight: 600; color: var(--ink); margin-bottom: 4px; }
  .order-items { flex: 1; overflow-y: auto; min-height: 80px; font-variant-numeric: tabular-nums; margin-top: 12px; }
  .order-line { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px dashed var(--paper-edge); font-size: 14px; gap: 10px; }
  .order-line .lineName { flex: 1; }
  .order-line .lineQty { color: var(--text-muted); font-size: 12px; display: block; margin-top: 2px; }
  .order-totals { border-top: 2px solid var(--ink); padding-top: 10px; margin-top: 8px; font-variant-numeric: tabular-nums; }
  .totalLine { display: flex; justify-content: space-between; padding: 3px 0; font-size: 13px; color: var(--text-muted); }
  .grandTotal { display: flex; justify-content: space-between; align-items: baseline; padding-top: 8px; font-family: 'Fraunces', serif; font-size: 26px; font-weight: 600; color: var(--ink); }
  .btn-primary { background: var(--brass); }
  .btn-primary:hover { background: var(--brass-bright); }
  #receiptSection { display: none; margin-top: 24px; padding-top: 24px; border-top: 2px dashed var(--paper-edge); }

  @media (max-width: 860px) {
    .pos-layout { grid-template-columns: 1fr; }
    .pos-right { border-left: none; border-top: 3px solid var(--ink); position: static; min-height: auto; }
    .pos-left, .pos-right { padding: 16px; }
    .topBar { padding: 12px 16px; }
    .tabBar { padding: 0 16px; }
    .padded-panel { padding: 16px; }
  }
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
    <label>What type of business is this?</label>
    <div class="bizTypeGrid">
      <button type="button" class="bizTypeBtn" data-type="retail">
        <span class="bizTypeName">Retail</span>
        <span class="bizTypeDesc">Shop selling physical products</span>
      </button>
      <button type="button" class="bizTypeBtn" data-type="food_beverage">
        <span class="bizTypeName">Food &amp; Beverage</span>
        <span class="bizTypeDesc">Cafe, restaurant, food stall</span>
      </button>
      <button type="button" class="bizTypeBtn" data-type="service">
        <span class="bizTypeName">Service</span>
        <span class="bizTypeDesc">Tuition, salon, clinic, and similar</span>
      </button>
      <button type="button" class="bizTypeBtn" data-type="other">
        <span class="bizTypeName">Other</span>
        <span class="bizTypeDesc">Doesn't fit the above</span>
      </button>
    </div>
    <input type="hidden" id="setupBusinessType" value="" />
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
    <div class="topBar">
      <span class="brand-mark">HarminPOS</span>
      <span class="topBarUser" id="welcomeMsg"></span>
    </div>

    <div class="tabBar">
      <button id="tabCheckoutBtn" class="tabBtn">Checkout</button>
      <button id="tabProductsBtn" class="tabBtn">Products</button>
      <button id="tabSuppliersBtn" class="tabBtn">Suppliers</button>
      <button id="tabReportsBtn" class="tabBtn">Reports</button>
      <button id="tabStaffBtn" class="tabBtn">Staff</button>
      <button id="tabSettingsBtn" class="tabBtn">Settings</button>
    </div>

    <div id="checkoutTab" class="pos-layout">
      <div class="pos-left">
        <div id="shiftClosedView">
          <h2 class="sectionTitle" style="margin-top: 0;">Open your shift</h2>
          <p class="sub" style="margin-bottom: 0;">Count your starting cash before you can make sales.</p>
          <label for="openingCash">Starting cash (RM)</label>
          <input id="openingCash" type="number" step="0.01" min="0" />
          <button id="openShiftBtn">Open shift</button>
          <div id="openShiftMsg"></div>
        </div>

        <div id="shiftOpenView">
          <p class="sub" id="shiftStatusText" style="margin-bottom: 0;"></p>
          <button id="closeShiftBtn" class="smallBtn" style="margin-left: 0;">Close shift</button>
          <div id="closeShiftForm" style="display: none; margin-top: 16px;">
            <label for="closingCash">Counted cash (RM)</label>
            <input id="closingCash" type="number" step="0.01" min="0" />
            <button id="confirmCloseShiftBtn">Confirm close</button>
          </div>
          <div id="closeShiftMsg"></div>
        </div>

        <input id="posSearch" type="text" placeholder="Search products..." />
        <div id="checkoutProductList" class="product-grid"></div>
      </div>

      <div class="pos-right">
        <div class="order-header">Current Order</div>
        <div id="cartItems" class="order-items"></div>
        <div id="cartTotals" class="order-totals"></div>
        <label for="discountInput">Discount (RM, optional)</label>
        <input id="discountInput" type="number" step="0.01" min="0" placeholder="0.00" />
        <label for="paymentMethod">Payment method</label>
        <select id="paymentMethod">
          <option value="cash">Cash</option>
          <option value="duitnow_qr">DuitNow QR</option>
          <option value="card">Card</option>
        </select>
        <button id="checkoutBtn" class="btn-primary">Complete sale</button>
        <div id="checkoutMsg"></div>

        <div id="receiptSection">
          <h2 class="sectionTitle" style="margin-top: 0;">Sale complete</h2>
          <p class="sub">Receipt <span id="receiptNumber"></span></p>
          <div id="receiptItems"></div>
          <div class="productRow totalRow"><span>Total</span><span id="receiptTotal"></span></div>
          <button id="newSaleBtn">New sale</button>
        </div>
      </div>
    </div>

    <div id="productsTab" class="padded-panel">
      <h2 class="sectionTitle">All products</h2>
      <div id="manageProductList"></div>

      <div id="addProductSection">
        <h2 class="sectionTitle" id="productFormTitle">Add a product</h2>
        <p class="toggle" id="cancelEditRow" style="display: none; text-align: left; margin-top: 0;">
          <a id="cancelEditBtn">Cancel editing</a>
        </p>
        <label for="prodName">Name</label>
        <input id="prodName" type="text" />
        <label for="prodType">Type</label>
        <select id="prodType">
          <option value="goods">Goods (physical item)</option>
          <option value="service">Service</option>
        </select>
        <label for="prodPrice">Price (RM)</label>
        <input id="prodPrice" type="number" step="0.01" min="0" />
        <label for="prodCost">Cost price (RM, optional)</label>
        <input id="prodCost" type="number" step="0.01" min="0" />
        <label for="prodSku">SKU (optional)</label>
        <input id="prodSku" type="text" />
        <div id="stockFields">
          <label for="prodStock">Stock quantity</label>
          <input id="prodStock" type="number" min="0" />
        </div>
        <label class="inlineLabel"><input type="checkbox" id="prodSstApplicable" /> SST applicable</label>
        <div id="sstRateField" style="display: none;">
          <label for="prodSstRate">SST rate (%)</label>
          <input id="prodSstRate" type="number" step="0.01" min="0" max="100" placeholder="e.g. 6" />
        </div>
        <label for="prodSupplier">Supplier (optional)</label>
        <select id="prodSupplier">
          <option value="">None</option>
        </select>
        <button id="addProductBtn">Add product</button>
        <div id="addProductMsg"></div>
      </div>
    </div>

    <div id="suppliersTab" class="padded-panel">
      <h2 class="sectionTitle" style="margin-top: 0;">Suppliers</h2>
      <div id="supplierList"></div>

      <h2 class="sectionTitle">Add a supplier</h2>
      <label for="newSupplierName">Supplier name</label>
      <input id="newSupplierName" type="text" />
      <label for="newSupplierContact">Contact person (optional)</label>
      <input id="newSupplierContact" type="text" />
      <label for="newSupplierPhone">Phone (optional)</label>
      <input id="newSupplierPhone" type="text" />
      <button id="addSupplierBtn">Add supplier</button>
      <div id="addSupplierMsg"></div>
    </div>

    <div id="reportsTab" class="padded-panel">
      <div style="display: flex; gap: 8px; margin-bottom: 16px;">
        <button id="rangeTodayBtn" class="smallBtn" style="margin: 0;">Today</button>
        <button id="rangeWeekBtn" class="smallBtn" style="margin: 0;">7 days</button>
        <button id="rangeMonthBtn" class="smallBtn" style="margin: 0;">30 days</button>
      </div>
      <h2 class="sectionTitle" style="margin-top: 0;" id="reportRangeTitle">Today</h2>
      <div class="productRow"><span>Sales</span><span id="reportSaleCount"></span></div>
      <div class="productRow"><span>Revenue</span><span id="reportRevenue"></span></div>
      <div class="productRow totalRow"><span>Profit</span><span id="reportProfit"></span></div>

      <h2 class="sectionTitle">By employee</h2>
      <div id="employeePerformanceList"></div>

      <h2 class="sectionTitle">Recent sales</h2>
      <div id="salesHistoryList"></div>
    </div>

    <div id="staffTab" class="padded-panel">
      <h2 class="sectionTitle">Team</h2>
      <div id="staffListManage"></div>

      <h2 class="sectionTitle">Add team member</h2>
      <label for="newStaffName">Name</label>
      <input id="newStaffName" type="text" />
      <label for="newStaffEmail">Email</label>
      <input id="newStaffEmail" type="email" />
      <label for="newStaffPassword">Temporary password</label>
      <input id="newStaffPassword" type="password" />
      <label for="newStaffRole">Role</label>
      <select id="newStaffRole"></select>
      <button id="addStaffBtn">Add team member</button>
      <div id="addStaffMsg"></div>
    </div>

    <div id="settingsTab" class="padded-panel">
      <h2 class="sectionTitle" style="margin-top: 0;">Business details</h2>
      <p class="sub">Used on receipts and required for LHDN e-Invoice submissions.</p>
      <label for="bizLegalName">Legal business name</label>
      <input id="bizLegalName" type="text" />
      <label for="bizTradingName">Trading name (optional)</label>
      <input id="bizTradingName" type="text" />
      <label for="bizSsm">SSM registration number</label>
      <input id="bizSsm" type="text" />
      <label for="bizTin">TIN (LHDN Tax ID)</label>
      <input id="bizTin" type="text" />
      <label for="bizSst">SST registration number (optional)</label>
      <input id="bizSst" type="text" />
      <label for="bizMsic">MSIC code (optional)</label>
      <input id="bizMsic" type="text" />
      <label for="bizPhone">Phone</label>
      <input id="bizPhone" type="text" />
      <label for="bizEmail">Email</label>
      <input id="bizEmail" type="email" />
      <label for="bizAddress1">Address line 1</label>
      <input id="bizAddress1" type="text" />
      <label for="bizCity">City</label>
      <input id="bizCity" type="text" />
      <label for="bizState">State</label>
      <input id="bizState" type="text" />
      <label for="bizPostcode">Postcode</label>
      <input id="bizPostcode" type="text" />
      <button id="saveBusinessBtn">Save business details</button>
      <div id="saveBusinessMsg"></div>

      <h2 class="sectionTitle">Trusted devices</h2>
      <div id="deviceList"></div>

      <h2 class="sectionTitle">Audit log</h2>
      <p class="sub">Every login, sale, void, and account change -- most recent first.</p>
      <div id="auditLogList"></div>
    </div>
  </div>

<script>
let pendingEmail = "";
let selectedStaffId = null;
let countdownInterval = null;
let cart = [];
let allProducts = [];

function showTab(tab) {
  document.getElementById("checkoutTab").style.display = tab === "checkout" ? "grid" : "none";
  document.getElementById("productsTab").style.display = tab === "products" ? "block" : "none";
  document.getElementById("suppliersTab").style.display = tab === "suppliers" ? "block" : "none";
  document.getElementById("reportsTab").style.display = tab === "reports" ? "block" : "none";
  document.getElementById("staffTab").style.display = tab === "staff" ? "block" : "none";
  document.getElementById("settingsTab").style.display = tab === "settings" ? "block" : "none";
  document.getElementById("tabCheckoutBtn").className = "tabBtn" + (tab === "checkout" ? " active" : "");
  document.getElementById("tabProductsBtn").className = "tabBtn" + (tab === "products" ? " active" : "");
  document.getElementById("tabSuppliersBtn").className = "tabBtn" + (tab === "suppliers" ? " active" : "");
  document.getElementById("tabReportsBtn").className = "tabBtn" + (tab === "reports" ? " active" : "");
  document.getElementById("tabStaffBtn").className = "tabBtn" + (tab === "staff" ? " active" : "");
  document.getElementById("tabSettingsBtn").className = "tabBtn" + (tab === "settings" ? " active" : "");
  if (tab === "suppliers") loadSuppliers();
  if (tab === "reports") {
    loadReports();
    loadSalesHistory();
  }
  if (tab === "staff") loadStaffTab();
  if (tab === "settings") {
    loadBusinessSettings();
    loadDevices();
    loadAuditLog();
  }
}

document.getElementById("tabCheckoutBtn").addEventListener("click", () => showTab("checkout"));
document.getElementById("tabProductsBtn").addEventListener("click", () => showTab("products"));
document.getElementById("tabSuppliersBtn").addEventListener("click", () => showTab("suppliers"));
document.getElementById("tabReportsBtn").addEventListener("click", () => showTab("reports"));
document.getElementById("tabStaffBtn").addEventListener("click", () => showTab("staff"));
document.getElementById("tabSettingsBtn").addEventListener("click", () => showTab("settings"));

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

document.querySelectorAll(".bizTypeBtn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".bizTypeBtn").forEach((b) => b.classList.remove("selected"));
    btn.classList.add("selected");
    document.getElementById("setupBusinessType").value = btn.dataset.type;
  });
});

document.getElementById("setupBtn").addEventListener("click", async () => {
  const name = document.getElementById("name").value.trim();
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;
  const business_type = document.getElementById("setupBusinessType").value;
  const msg = document.getElementById("setupMsg");
  msg.textContent = "";

  if (!business_type) {
    msg.textContent = "Choose a business type above.";
    msg.className = "error";
    return;
  }

  const res = await fetch("/api/setup", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name, email, password, business_type }),
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

let allSuppliers = [];
let currentUserRole = null;
let editingProductId = null;

async function loadDashboard() {
  const me = await fetch("/api/me").then((r) => r.json());
  currentUserRole = me.role;
  document.getElementById("welcomeMsg").textContent = "Logged in as " + me.name + " (" + me.role + ")";
  // If this business was set up as a service business, default new items
  // to "service" instead of "goods" -- reduces the exact kind of mistake
  // where a service gets added with a stock count by accident.
  if (me.business_type === "service") {
    document.getElementById("prodType").value = "service";
    document.getElementById("stockFields").style.display = "none";
  }
  // Cashiers live on the Checkout tab -- everything else is management territory.
  document.getElementById("tabProductsBtn").style.display = me.role === "cashier" ? "none" : "inline-block";
  document.getElementById("tabSuppliersBtn").style.display = me.role === "cashier" ? "none" : "inline-block";
  document.getElementById("tabReportsBtn").style.display = me.role === "cashier" ? "none" : "inline-block";
  document.getElementById("tabStaffBtn").style.display = ["owner", "admin"].includes(me.role)
    ? "inline-block"
    : "none";
  document.getElementById("tabSettingsBtn").style.display = me.role === "owner" ? "inline-block" : "none";
  populateRoleDropdown();
  cart = [];
  renderCart();
  await loadProducts();
  await loadSuppliers();
  await loadShiftStatus();
  showTab("checkout");
  showOnly("dashboardSection");
}

async function loadProducts() {
  const res = await fetch("/api/products");
  const data = await res.json();
  allProducts = data.products || [];
  renderCheckoutProductList();
  renderManageProductList();
}

function renderCheckoutProductList() {
  const container = document.getElementById("checkoutProductList");
  container.innerHTML = "";

  const query = document.getElementById("posSearch").value.trim().toLowerCase();
  const visible = query ? allProducts.filter((p) => p.name.toLowerCase().includes(query)) : allProducts;

  if (allProducts.length === 0) {
    container.innerHTML = '<p class="sub">No products yet -- add one in the Products tab.</p>';
    return;
  }
  if (visible.length === 0) {
    container.innerHTML = '<p class="sub">No products match "' + query + '".</p>';
    return;
  }

  visible.forEach((p) => {
    const card = document.createElement("button");
    card.className = "product-card";
    const lowStock = p.item_type === "goods" && p.reorder_level !== null && p.stock_quantity <= p.reorder_level;
    const stockText = p.item_type === "goods" ? "Stock: " + (p.stock_quantity ?? 0) : "Service";
    card.innerHTML =
      '<div class="p-name">' +
      p.name +
      '</div><div class="p-price">RM ' +
      p.unit_price_display +
      '</div><div class="p-meta' +
      (lowStock ? " lowStock" : "") +
      '">' +
      stockText +
      (lowStock ? " -- Low stock" : "") +
      "</div>";
    card.addEventListener("click", () => addToCart(p));
    container.appendChild(card);
  });
}

document.getElementById("posSearch").addEventListener("input", renderCheckoutProductList);

function renderManageProductList() {
  const container = document.getElementById("manageProductList");
  container.innerHTML = "";

  if (allProducts.length === 0) {
    container.innerHTML = '<p class="sub">No products yet.</p>';
    return;
  }

  allProducts.forEach((p) => {
    const row = document.createElement("div");
    row.className = "productRow";
    const lowStock = p.item_type === "goods" && p.reorder_level !== null && p.stock_quantity <= p.reorder_level;
    const stockText = p.item_type === "goods" ? "Stock: " + (p.stock_quantity ?? 0) : "Service";
    row.innerHTML =
      "<span>" +
      p.name +
      "</span><span>RM " +
      p.unit_price_display +
      '</span><span class="' +
      (lowStock ? "lowStock" : "") +
      '">' +
      stockText +
      (lowStock ? " -- Low stock" : "") +
      "</span>";
    const removeBtn = document.createElement("button");
    removeBtn.textContent = "Remove";
    removeBtn.className = "smallBtn";
    removeBtn.addEventListener("click", async () => {
      if (!confirm("Remove " + p.name + "? This can't easily be undone.")) return;
      const res = await fetch("/api/products/remove", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ product_id: p.id }),
      });
      if (res.ok) {
        await loadProducts();
      }
    });
    const editBtn = document.createElement("button");
    editBtn.textContent = "Edit";
    editBtn.className = "smallBtn";
    editBtn.addEventListener("click", () => startEditingProduct(p));
    row.appendChild(editBtn);
    row.appendChild(removeBtn);
    container.appendChild(row);
  });
}

document.getElementById("prodType").addEventListener("change", (e) => {
  document.getElementById("stockFields").style.display = e.target.value === "goods" ? "block" : "none";
});

document.getElementById("prodSstApplicable").addEventListener("change", (e) => {
  document.getElementById("sstRateField").style.display = e.target.checked ? "block" : "none";
});

function startEditingProduct(p) {
  editingProductId = p.id;
  document.getElementById("productFormTitle").textContent = "Edit product";
  document.getElementById("addProductBtn").textContent = "Save changes";
  document.getElementById("cancelEditRow").style.display = "block";

  document.getElementById("prodName").value = p.name;
  document.getElementById("prodType").value = p.item_type;
  document.getElementById("stockFields").style.display = p.item_type === "goods" ? "block" : "none";
  document.getElementById("prodPrice").value = p.unit_price_display;
  document.getElementById("prodCost").value = p.cost_price_display || "";
  document.getElementById("prodSku").value = p.sku || "";
  document.getElementById("prodStock").value = p.stock_quantity ?? "";
  document.getElementById("prodSstApplicable").checked = !!p.sst_applicable;
  document.getElementById("sstRateField").style.display = p.sst_applicable ? "block" : "none";
  document.getElementById("prodSstRate").value = p.sst_applicable ? (p.sst_rate * 100).toFixed(2) : "";
  document.getElementById("prodSupplier").value = p.supplier_id || "";

  document.getElementById("productFormTitle").scrollIntoView({ behavior: "smooth", block: "center" });
}

function resetProductForm() {
  editingProductId = null;
  document.getElementById("productFormTitle").textContent = "Add a product";
  document.getElementById("addProductBtn").textContent = "Add product";
  document.getElementById("cancelEditRow").style.display = "none";
  document.getElementById("prodName").value = "";
  document.getElementById("prodPrice").value = "";
  document.getElementById("prodCost").value = "";
  document.getElementById("prodSku").value = "";
  document.getElementById("prodStock").value = "";
  document.getElementById("prodSstApplicable").checked = false;
  document.getElementById("prodSstRate").value = "";
  document.getElementById("sstRateField").style.display = "none";
  document.getElementById("prodSupplier").value = "";
}

document.getElementById("cancelEditBtn").addEventListener("click", resetProductForm);

document.getElementById("addProductBtn").addEventListener("click", async () => {
  const name = document.getElementById("prodName").value.trim();
  const item_type = document.getElementById("prodType").value;
  const unit_price = document.getElementById("prodPrice").value;
  const cost_price = document.getElementById("prodCost").value;
  const sku = document.getElementById("prodSku").value.trim();
  const stock_quantity = document.getElementById("prodStock").value;
  const sstApplicable = document.getElementById("prodSstApplicable").checked;
  const sstRatePercent = document.getElementById("prodSstRate").value;
  const supplier_id = document.getElementById("prodSupplier").value;
  const msg = document.getElementById("addProductMsg");
  msg.textContent = "";

  const payload = {
    name,
    item_type,
    unit_price,
    cost_price: cost_price || undefined,
    sku: sku || undefined,
    stock_quantity: item_type === "goods" ? Number(stock_quantity || 0) : undefined,
    sst_applicable: sstApplicable,
    sst_rate: sstApplicable ? Number(sstRatePercent || 0) / 100 : undefined,
    supplier_id: supplier_id || undefined,
  };

  const isEditing = editingProductId !== null;
  if (isEditing) payload.product_id = editingProductId;

  const res = await fetch(isEditing ? "/api/products/edit" : "/api/products", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json();

  if (!res.ok) {
    msg.textContent = data.error;
    msg.className = "error";
    return;
  }

  msg.textContent = isEditing ? "Product updated!" : "Product added!";
  msg.className = "success";
  resetProductForm();
  await loadProducts();
});

function addToCart(product) {
  const existing = cart.find((c) => c.product_id === product.id);
  if (existing) {
    existing.quantity += 1;
  } else {
    cart.push({
      product_id: product.id,
      name: product.name,
      unit_price: Number(product.unit_price_display),
      sst_applicable: product.sst_applicable,
      sst_rate: product.sst_rate,
      quantity: 1,
    });
  }
  renderCart();
}

function renderCart() {
  const container = document.getElementById("cartItems");
  container.innerHTML = "";

  if (cart.length === 0) {
    container.innerHTML = '<p class="sub">Tap a product to start an order.</p>';
    document.getElementById("cartTotals").innerHTML = "";
    return;
  }

  let subtotal = 0;
  let sstTotal = 0;

  cart.forEach((item, index) => {
    const lineSubtotal = item.unit_price * item.quantity;
    const lineSst = item.sst_applicable ? lineSubtotal * (item.sst_rate || 0) : 0;
    subtotal += lineSubtotal;
    sstTotal += lineSst;

    const row = document.createElement("div");
    row.className = "order-line";
    row.innerHTML =
      '<span class="lineName">' +
      item.name +
      '<span class="lineQty">Qty ' +
      item.quantity +
      "</span></span><span>RM " +
      (lineSubtotal + lineSst).toFixed(2) +
      "</span>";
    const removeBtn = document.createElement("button");
    removeBtn.textContent = "Remove";
    removeBtn.className = "smallBtn";
    removeBtn.addEventListener("click", () => {
      cart.splice(index, 1);
      renderCart();
    });
    row.appendChild(removeBtn);
    container.appendChild(row);
  });

  const discount = Number(document.getElementById("discountInput").value) || 0;
  const total = Math.max(0, subtotal + sstTotal - discount);
  document.getElementById("cartTotals").innerHTML =
    '<div class="totalLine"><span>Subtotal</span><span>RM ' +
    subtotal.toFixed(2) +
    '</span></div><div class="totalLine"><span>SST</span><span>RM ' +
    sstTotal.toFixed(2) +
    '</span></div><div class="totalLine"><span>Discount</span><span>-RM ' +
    discount.toFixed(2) +
    '</span></div><div class="grandTotal"><span>Total</span><span>RM ' +
    total.toFixed(2) +
    "</span></div>";
}

document.getElementById("discountInput").addEventListener("input", renderCart);

document.getElementById("checkoutBtn").addEventListener("click", async () => {
  const msg = document.getElementById("checkoutMsg");
  msg.textContent = "";

  if (cart.length === 0) {
    msg.textContent = "Cart is empty.";
    msg.className = "error";
    return;
  }

  const payment_method = document.getElementById("paymentMethod").value;
  const discount_amount = document.getElementById("discountInput").value || undefined;

  const res = await fetch("/api/sales", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      items: cart.map((c) => ({ product_id: c.product_id, quantity: c.quantity })),
      payment_method,
      discount_amount,
    }),
  });
  const data = await res.json();

  if (!res.ok) {
    msg.textContent = data.error;
    msg.className = "error";
    return;
  }

  cart = [];
  document.getElementById("discountInput").value = "";
  renderCart();
  showReceipt(data.sale);
  await loadProducts(); // stock counts just changed, refresh the list
});

function showReceipt(sale) {
  const container = document.getElementById("receiptItems");
  container.innerHTML = "";
  sale.items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "productRow";
    row.innerHTML = "<span>" + item.name + " x" + item.quantity + "</span><span>RM " + item.line_total + "</span>";
    container.appendChild(row);
  });
  if (Number(sale.discount_amount) > 0) {
    const discountRow = document.createElement("div");
    discountRow.className = "productRow";
    discountRow.innerHTML = "<span>Discount</span><span>-RM " + sale.discount_amount + "</span>";
    container.appendChild(discountRow);
  }
  document.getElementById("receiptNumber").textContent = sale.receipt_number;
  document.getElementById("receiptTotal").textContent = "RM " + sale.total_amount;
  document.getElementById("receiptSection").style.display = "block";
}

document.getElementById("newSaleBtn").addEventListener("click", () => {
  document.getElementById("receiptSection").style.display = "none";
});

async function loadShiftStatus() {
  const res = await fetch("/api/shifts/current");
  const data = await res.json();

  if (data.open) {
    document.getElementById("shiftClosedView").style.display = "none";
    document.getElementById("shiftOpenView").style.display = "block";
    document.getElementById("shiftStatusText").textContent =
      "Shift open -- starting cash RM " + data.opening_cash;
    document.getElementById("checkoutBtn").disabled = false;
  } else {
    document.getElementById("shiftClosedView").style.display = "block";
    document.getElementById("shiftOpenView").style.display = "none";
    document.getElementById("checkoutBtn").disabled = true;
  }
}

document.getElementById("openShiftBtn").addEventListener("click", async () => {
  const opening_cash = document.getElementById("openingCash").value;
  const msg = document.getElementById("openShiftMsg");
  msg.textContent = "";

  const res = await fetch("/api/shifts/open", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ opening_cash }),
  });
  const data = await res.json();

  if (!res.ok) {
    msg.textContent = data.error;
    msg.className = "error";
    return;
  }

  document.getElementById("openingCash").value = "";
  await loadShiftStatus();
});

document.getElementById("closeShiftBtn").addEventListener("click", () => {
  document.getElementById("closeShiftForm").style.display = "block";
});

document.getElementById("confirmCloseShiftBtn").addEventListener("click", async () => {
  const closing_cash_actual = document.getElementById("closingCash").value;
  const msg = document.getElementById("closeShiftMsg");
  msg.textContent = "";

  const res = await fetch("/api/shifts/close", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ closing_cash_actual }),
  });
  const data = await res.json();

  if (!res.ok) {
    msg.textContent = data.error;
    msg.className = "error";
    return;
  }

  msg.textContent =
    "Shift closed. Expected RM " + data.expected + ", counted RM " + data.actual + ", difference RM " + data.discrepancy + ".";
  msg.className = data.discrepancy === "0.00" ? "success" : "error";
  document.getElementById("closingCash").value = "";
  document.getElementById("closeShiftForm").style.display = "none";
  await loadShiftStatus();
});

let currentReportRange = "today";

async function loadReports() {
  const res = await fetch("/api/reports/summary?range=" + currentReportRange);
  const data = await res.json();
  if (!res.ok) return;
  document.getElementById("reportSaleCount").textContent = data.sale_count;
  document.getElementById("reportRevenue").textContent = "RM " + data.revenue;
  document.getElementById("reportProfit").textContent = "RM " + data.profit;

  const titles = { today: "Today", week: "Last 7 days", month: "Last 30 days" };
  document.getElementById("reportRangeTitle").textContent = titles[currentReportRange];

  ["rangeTodayBtn", "rangeWeekBtn", "rangeMonthBtn"].forEach((id) => {
    document.getElementById(id).style.background = "white";
    document.getElementById(id).style.color = "var(--ink)";
  });
  const activeId = { today: "rangeTodayBtn", week: "rangeWeekBtn", month: "rangeMonthBtn" }[currentReportRange];
  document.getElementById(activeId).style.background = "var(--ink)";
  document.getElementById(activeId).style.color = "white";

  await loadEmployeePerformance();
}

async function loadEmployeePerformance() {
  const res = await fetch("/api/reports/employees?range=" + currentReportRange);
  const data = await res.json();
  const container = document.getElementById("employeePerformanceList");
  container.innerHTML = "";

  if (!res.ok) {
    container.innerHTML = ""; // staff role: not permitted, just show nothing
    return;
  }
  if (!data.performance || data.performance.length === 0) {
    container.innerHTML = '<p class="sub">No sales in this period yet.</p>';
    return;
  }

  data.performance.forEach((p) => {
    const row = document.createElement("div");
    row.className = "productRow";
    const voidNote = p.void_count > 0 ? ", " + p.void_count + " voided" : "";
    row.innerHTML =
      "<span>" + p.name + "</span><span>" + p.sale_count + " sales" + voidNote + "</span><span>RM " + p.revenue_display + "</span>";
    container.appendChild(row);
  });
}

document.getElementById("rangeTodayBtn").addEventListener("click", () => {
  currentReportRange = "today";
  loadReports();
});
document.getElementById("rangeWeekBtn").addEventListener("click", () => {
  currentReportRange = "week";
  loadReports();
});
document.getElementById("rangeMonthBtn").addEventListener("click", () => {
  currentReportRange = "month";
  loadReports();
});

async function loadSuppliers() {
  const res = await fetch("/api/suppliers");
  const data = await res.json();
  allSuppliers = data.suppliers || [];
  renderSupplierList();
  renderSupplierDropdown();
}

function renderSupplierList() {
  const container = document.getElementById("supplierList");
  container.innerHTML = "";
  if (allSuppliers.length === 0) {
    container.innerHTML = '<p class="sub">No suppliers yet.</p>';
    return;
  }
  allSuppliers.forEach((s) => {
    const row = document.createElement("div");
    row.className = "productRow";
    row.innerHTML =
      "<span>" + s.name + "</span><span>" + (s.contact_person || "") + "</span><span>" + (s.phone || "") + "</span>";
    container.appendChild(row);
  });
}

function renderSupplierDropdown() {
  const select = document.getElementById("prodSupplier");
  select.innerHTML = '<option value="">None</option>';
  allSuppliers.forEach((s) => {
    const opt = document.createElement("option");
    opt.value = s.id;
    opt.textContent = s.name;
    select.appendChild(opt);
  });
}

document.getElementById("addSupplierBtn").addEventListener("click", async () => {
  const name = document.getElementById("newSupplierName").value.trim();
  const contact_person = document.getElementById("newSupplierContact").value.trim();
  const phone = document.getElementById("newSupplierPhone").value.trim();
  const msg = document.getElementById("addSupplierMsg");
  msg.textContent = "";

  const res = await fetch("/api/suppliers", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      name,
      contact_person: contact_person || undefined,
      phone: phone || undefined,
    }),
  });
  const data = await res.json();

  if (!res.ok) {
    msg.textContent = data.error;
    msg.className = "error";
    return;
  }

  msg.textContent = "Supplier added!";
  msg.className = "success";
  document.getElementById("newSupplierName").value = "";
  document.getElementById("newSupplierContact").value = "";
  document.getElementById("newSupplierPhone").value = "";
  await loadSuppliers();
});

function populateRoleDropdown() {
  const select = document.getElementById("newStaffRole");
  select.innerHTML = "";
  // Only the owner can create another admin -- matches the server-side check.
  const options =
    currentUserRole === "owner"
      ? [
          ["admin", "Admin"],
          ["staff", "Staff"],
          ["cashier", "Cashier"],
        ]
      : [
          ["staff", "Staff"],
          ["cashier", "Cashier"],
        ];
  options.forEach(([value, label]) => {
    const opt = document.createElement("option");
    opt.value = value;
    opt.textContent = label;
    select.appendChild(opt);
  });
}

async function loadStaffTab() {
  const res = await fetch("/api/users");
  const data = await res.json();
  const container = document.getElementById("staffListManage");
  container.innerHTML = "";
  (data.users || []).forEach((u) => {
    const row = document.createElement("div");
    row.className = "productRow";
    row.innerHTML = "<span>" + u.name + "</span><span>" + u.email + "</span><span>" + u.role + "</span>";
    if (u.role !== "owner") {
      const resetPinBtn = document.createElement("button");
      resetPinBtn.textContent = "Reset PIN";
      resetPinBtn.className = "smallBtn";
      resetPinBtn.addEventListener("click", async () => {
        if (!confirm("Reset " + u.name + "'s PIN? They'll need to log in with their password and set a new one.")) return;
        const res2 = await fetch("/api/users/reset-pin", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ user_id: u.id }),
        });
        if (!res2.ok) {
          const errData = await res2.json();
          alert(errData.error);
        }
      });
      row.appendChild(resetPinBtn);

      const deactivateBtn = document.createElement("button");
      deactivateBtn.textContent = "Deactivate";
      deactivateBtn.className = "smallBtn";
      deactivateBtn.addEventListener("click", async () => {
        if (!confirm("Deactivate " + u.name + "? They'll lose access immediately.")) return;
        const res2 = await fetch("/api/users/deactivate", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ user_id: u.id }),
        });
        if (res2.ok) {
          await loadStaffTab();
        } else {
          const errData = await res2.json();
          alert(errData.error);
        }
      });
      row.appendChild(deactivateBtn);
    }
    container.appendChild(row);
  });
}

document.getElementById("addStaffBtn").addEventListener("click", async () => {
  const name = document.getElementById("newStaffName").value.trim();
  const email = document.getElementById("newStaffEmail").value.trim();
  const password = document.getElementById("newStaffPassword").value;
  const role = document.getElementById("newStaffRole").value;
  const msg = document.getElementById("addStaffMsg");
  msg.textContent = "";

  const res = await fetch("/api/users", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name, email, password, role }),
  });
  const data = await res.json();

  if (!res.ok) {
    msg.textContent = data.error;
    msg.className = "error";
    return;
  }

  msg.textContent = "Team member added! Share the temporary password with them directly.";
  msg.className = "success";
  document.getElementById("newStaffName").value = "";
  document.getElementById("newStaffEmail").value = "";
  document.getElementById("newStaffPassword").value = "";
  await loadStaffTab();
});

async function loadSalesHistory() {
  const res = await fetch("/api/sales");
  const data = await res.json();
  const container = document.getElementById("salesHistoryList");
  container.innerHTML = "";

  if (!data.sales || data.sales.length === 0) {
    container.innerHTML = '<p class="sub">No sales yet.</p>';
    return;
  }

  data.sales.forEach((s) => {
    const row = document.createElement("div");
    row.className = "productRow";
    const statusText = s.is_voided ? " (voided)" : "";
    row.innerHTML =
      "<span>" +
      s.receipt_number +
      statusText +
      " -- " +
      s.cashier_name +
      "</span><span>RM " +
      s.total_display +
      "</span>";

    if (!s.is_voided && ["owner", "admin"].includes(currentUserRole)) {
      const voidBtn = document.createElement("button");
      voidBtn.textContent = "Void";
      voidBtn.className = "smallBtn";
      voidBtn.addEventListener("click", async () => {
        const reason = prompt("Reason for voiding this sale?");
        if (reason === null) return; // cancelled, do nothing
        const res2 = await fetch("/api/sales/void", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ sale_id: s.id, reason }),
        });
        if (res2.ok) {
          await loadSalesHistory();
          await loadReports();
          await loadProducts();
        } else {
          const errData = await res2.json();
          alert(errData.error);
        }
      });
      row.appendChild(voidBtn);
    }
    container.appendChild(row);
  });
}

async function loadBusinessSettings() {
  const res = await fetch("/api/business-profile");
  const data = await res.json();
  const p = data.profile;
  if (!p) return; // nothing saved yet, leave the form blank
  document.getElementById("bizLegalName").value = p.legal_name || "";
  document.getElementById("bizTradingName").value = p.trading_name || "";
  document.getElementById("bizSsm").value = p.ssm_registration_no || "";
  document.getElementById("bizTin").value = p.tin || "";
  document.getElementById("bizSst").value = p.sst_registration_no || "";
  document.getElementById("bizMsic").value = p.msic_code || "";
  document.getElementById("bizPhone").value = p.phone || "";
  document.getElementById("bizEmail").value = p.email || "";
  document.getElementById("bizAddress1").value = p.address_line1 || "";
  document.getElementById("bizCity").value = p.city || "";
  document.getElementById("bizState").value = p.state || "";
  document.getElementById("bizPostcode").value = p.postcode || "";
}

document.getElementById("saveBusinessBtn").addEventListener("click", async () => {
  const msg = document.getElementById("saveBusinessMsg");
  msg.textContent = "";

  const body = {
    legal_name: document.getElementById("bizLegalName").value.trim(),
    trading_name: document.getElementById("bizTradingName").value.trim() || undefined,
    ssm_registration_no: document.getElementById("bizSsm").value.trim(),
    tin: document.getElementById("bizTin").value.trim(),
    sst_registration_no: document.getElementById("bizSst").value.trim() || undefined,
    msic_code: document.getElementById("bizMsic").value.trim() || undefined,
    phone: document.getElementById("bizPhone").value.trim() || undefined,
    email: document.getElementById("bizEmail").value.trim() || undefined,
    address_line1: document.getElementById("bizAddress1").value.trim() || undefined,
    city: document.getElementById("bizCity").value.trim() || undefined,
    state: document.getElementById("bizState").value.trim() || undefined,
    postcode: document.getElementById("bizPostcode").value.trim() || undefined,
  };

  const res = await fetch("/api/business-profile", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();

  if (!res.ok) {
    msg.textContent = data.error;
    msg.className = "error";
    return;
  }

  msg.textContent = "Business details saved.";
  msg.className = "success";
});

async function loadDevices() {
  const res = await fetch("/api/devices");
  const data = await res.json();
  const container = document.getElementById("deviceList");
  container.innerHTML = "";

  if (!data.devices || data.devices.length === 0) {
    container.innerHTML = '<p class="sub">No trusted devices yet.</p>';
    return;
  }

  data.devices.forEach((d) => {
    const row = document.createElement("div");
    row.className = "productRow";
    const status = d.is_active ? "" : " (revoked)";
    row.innerHTML =
      "<span>" + d.device_name + status + "</span><span>Verified by " + d.verified_by_name + "</span>";

    if (d.is_active) {
      const revokeBtn = document.createElement("button");
      revokeBtn.textContent = "Revoke";
      revokeBtn.className = "smallBtn";
      revokeBtn.addEventListener("click", async () => {
        if (!confirm("Revoke trust for " + d.device_name + "? It will need full email verification again.")) return;
        const res2 = await fetch("/api/devices/revoke", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ device_id: d.id }),
        });
        if (res2.ok) await loadDevices();
      });
      row.appendChild(revokeBtn);
    }
    container.appendChild(row);
  });
}

async function loadAuditLog() {
  const res = await fetch("/api/audit-log");
  const data = await res.json();
  const container = document.getElementById("auditLogList");
  container.innerHTML = "";

  if (!data.logs || data.logs.length === 0) {
    container.innerHTML = '<p class="sub">No activity recorded yet.</p>';
    return;
  }

  data.logs.forEach((l) => {
    const row = document.createElement("div");
    row.className = "productRow";
    const who = l.user_name || "System";
    row.innerHTML = "<span>" + l.action + " -- " + who + "</span><span>" + l.created_at + "</span>";
    container.appendChild(row);
  });
}

checkDeviceStatus();
</script>
</body>
</html>`;