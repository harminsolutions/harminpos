-- HarminPOS initial schema
-- One database per client (single-tenant), so there is no business_id
-- column anywhere here -- this whole database belongs to one business.

PRAGMA foreign_keys = ON;

-- ============================================================
-- BUSINESS PROFILE
-- Single-row table holding this client's legal/tax details.
-- Needed for LHDN e-Invoice submissions (TIN, MSIC code, SST no.)
-- and for printing correct info on receipts.
-- ============================================================
CREATE TABLE business_profile (
  id INTEGER PRIMARY KEY CHECK (id = 1), -- enforces exactly one row
  legal_name TEXT NOT NULL,
  trading_name TEXT,
  ssm_registration_no TEXT NOT NULL,
  tin TEXT NOT NULL,                      -- LHDN Tax Identification Number
  sst_registration_no TEXT,               -- NULL if not SST-registered
  msic_code TEXT,                         -- Malaysia Standard Industrial Classification code, required for e-Invoice
  address_line1 TEXT,
  address_line2 TEXT,
  city TEXT,
  state TEXT,
  postcode TEXT,
  phone TEXT,
  email TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- USERS & AUTH
-- role hierarchy: owner (full access, only one who can delete the
-- business profile or remove other admins) > admin (day-to-day
-- full control: staff, reports, void approvals) > staff (manages
-- products/reports, no user management) > cashier (checkout only).
-- Mirrors the RBAC pattern already used on portal.harminsolutions.com.
-- ============================================================
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  phone TEXT,
  password_hash TEXT NOT NULL,            -- bcrypt hash, never plaintext
  role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'staff', 'cashier')),
  pin_hash TEXT,                          -- hashed PIN for fast login on trusted devices, NULL until set
  pin_failed_attempts INTEGER NOT NULL DEFAULT 0,
  pin_locked_until TEXT,                  -- NULL unless locked out from too many wrong PIN attempts
  is_active INTEGER NOT NULL DEFAULT 1,   -- disable instead of delete, keeps history intact
  last_login_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One-time codes for login 2FA (email OTP via Resend), same
-- pattern as the portal.
CREATE TABLE otp_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  code_hash TEXT NOT NULL,                -- store a hash, never the raw code
  purpose TEXT NOT NULL CHECK (purpose IN ('login', 'password_reset')),
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_otp_user ON otp_codes(user_id);

-- ============================================================
-- TRUSTED DEVICES
-- A device (till/tablet) earns trust once via full email +
-- password + OTP verification. After that, staff use a fast PIN
-- on that specific device instead of repeating the full login.
-- Trust belongs to the device, not any one staff member -- several
-- cashiers can PIN into the same trusted till.
-- ============================================================
CREATE TABLE trusted_devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_token TEXT NOT NULL UNIQUE,      -- long random token stored on the device itself
  device_name TEXT,                       -- e.g. 'Front counter tablet'
  verified_by INTEGER NOT NULL REFERENCES users(id), -- who completed the full verification
  is_active INTEGER NOT NULL DEFAULT 1,   -- owner/admin can revoke instantly if a device is lost or stolen
  trusted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TEXT
);

CREATE INDEX idx_devices_token ON trusted_devices(device_token);

-- ============================================================
-- CATALOG
-- item_type distinguishes physical stock (boutique retail) from
-- services (tuition sessions, salon treatments, dental procedures) --
-- stock fields simply stay NULL for services.
-- ============================================================
CREATE TABLE categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL
);

-- ============================================================
-- SUPPLIERS
-- Vendors your client buys stock from. One supplier per product
-- is enough for v1; extend to a join table later if a product
-- ever needs multiple suppliers.
-- ============================================================
CREATE TABLE suppliers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  contact_person TEXT,
  phone TEXT,
  email TEXT,
  address TEXT,
  notes TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sku TEXT UNIQUE,                        -- NULL allowed for services with no SKU
  name TEXT NOT NULL,
  description TEXT,
  category_id INTEGER REFERENCES categories(id),
  supplier_id INTEGER REFERENCES suppliers(id), -- NULL for services or unspecified source
  item_type TEXT NOT NULL CHECK (item_type IN ('goods', 'service')),
  unit_price INTEGER NOT NULL,            -- stored in sen (cents) to avoid float rounding errors
  cost_price INTEGER,                     -- sen, optional, for margin reporting
  unit_of_measure TEXT,                   -- 'pcs', 'session', 'hour', etc.
  classification_code TEXT,               -- LHDN e-Invoice item classification code
  sst_applicable INTEGER NOT NULL DEFAULT 0,
  sst_rate REAL,                          -- e.g. 0.06 for 6%, NULL if not applicable
  stock_quantity INTEGER,                 -- NULL for services
  reorder_level INTEGER,                  -- NULL for services; triggers low-stock warning
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_products_sku ON products(sku);
CREATE INDEX idx_products_category ON products(category_id);
CREATE INDEX idx_products_supplier ON products(supplier_id);

-- ============================================================
-- CUSTOMERS
-- Optional on most sales (walk-in/cash), but required when a
-- buyer needs an individual e-Invoice with their own TIN.
-- ============================================================
CREATE TABLE customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT,
  email TEXT,
  tin TEXT,                               -- buyer's TIN, needed for B2B e-Invoices
  address TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- CASH SHIFTS
-- One row per till session: a cashier opens with a counted
-- starting float, sales attach to that session, then it's closed
-- with an actual counted amount. discrepancy flags shortfalls or
-- overages automatically -- no one has to do the math by hand.
-- ============================================================
CREATE TABLE cash_shifts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cashier_id INTEGER NOT NULL REFERENCES users(id),
  opening_cash INTEGER NOT NULL,          -- sen, starting float counted at shift start
  closing_cash_expected INTEGER,          -- sen, system-calculated: opening + cash sales - cash refunds
  closing_cash_actual INTEGER,            -- sen, manually counted at shift end
  discrepancy INTEGER,                    -- sen, actual minus expected; NULL until closed
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
  notes TEXT,                             -- e.g. explanation for a discrepancy
  opened_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  closed_at TEXT
);

CREATE INDEX idx_shifts_cashier ON cash_shifts(cashier_id);
CREATE INDEX idx_shifts_status ON cash_shifts(status);

-- ============================================================
-- SALES
-- einvoice_status tracks the MyInvois submission lifecycle
-- separately from payment_status -- a sale can be fully paid
-- while its e-Invoice is still pending/failed submission.
-- Voids are soft (is_voided flag), never a hard delete, so the
-- audit trail always stays intact.
-- ============================================================
CREATE TABLE sales (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  receipt_number TEXT NOT NULL UNIQUE,    -- human-readable sequential number, e.g. INV-000123
  cashier_id INTEGER NOT NULL REFERENCES users(id),
  shift_id INTEGER REFERENCES cash_shifts(id), -- which till session this sale belongs to
  customer_id INTEGER REFERENCES customers(id), -- NULL for walk-in sales

  subtotal INTEGER NOT NULL,              -- sen
  sst_amount INTEGER NOT NULL DEFAULT 0,  -- sen
  discount_amount INTEGER NOT NULL DEFAULT 0, -- sen
  total_amount INTEGER NOT NULL,          -- sen

  payment_method TEXT NOT NULL CHECK (payment_method IN ('cash', 'duitnow_qr', 'card', 'other')),
  payment_gateway_ref TEXT,               -- transaction ID from Billplz/HitPay/etc., NULL for cash
  payment_status TEXT NOT NULL DEFAULT 'completed'
    CHECK (payment_status IN ('pending', 'completed', 'failed', 'refunded')),

  einvoice_status TEXT NOT NULL DEFAULT 'not_required'
    CHECK (einvoice_status IN ('not_required', 'pending', 'submitted', 'validated', 'failed')),
  einvoice_uuid TEXT,                     -- LHDN's unique ID once validated

  is_voided INTEGER NOT NULL DEFAULT 0,
  voided_by INTEGER REFERENCES users(id),
  voided_reason TEXT,

  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sales_created ON sales(created_at);
CREATE INDEX idx_sales_cashier ON sales(cashier_id);
CREATE INDEX idx_sales_receipt ON sales(receipt_number);
CREATE INDEX idx_sales_shift ON sales(shift_id);

-- Line items. Product name/price are snapshotted at sale time so
-- historical receipts stay accurate even if a product is later
-- renamed or repriced.
CREATE TABLE sale_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sale_id INTEGER NOT NULL REFERENCES sales(id),
  product_id INTEGER REFERENCES products(id), -- kept even if product later deleted
  product_name_snapshot TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  unit_price_snapshot INTEGER NOT NULL,   -- sen
  cost_price_snapshot INTEGER,            -- sen, product's cost at time of sale -- enables accurate profit reporting even after supplier prices change
  sst_rate_snapshot REAL,
  line_total INTEGER NOT NULL             -- sen
);

CREATE INDEX idx_sale_items_sale ON sale_items(sale_id);

-- ============================================================
-- AUDIT LOG
-- Every security-relevant action gets a row here: logins, failed
-- logins, voids, deletions, role changes. Never overwritten,
-- never deleted -- this is what makes "secured" a real claim
-- instead of just a marketing word.
-- ============================================================
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id),   -- NULL for system-triggered events
  action TEXT NOT NULL,                   -- e.g. 'sale_voided', 'login_failed', 'product_deleted'
  entity_type TEXT,
  entity_id INTEGER,
  details TEXT,                           -- JSON blob with extra context
  ip_address TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_user ON audit_log(user_id);
CREATE INDEX idx_audit_created ON audit_log(created_at);