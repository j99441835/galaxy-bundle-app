const express = require('express');
const crypto = require('crypto');

const CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const APP_URL = process.env.APP_URL;
const SCOPES = 'write_discounts';

// Used to sign/verify the OAuth state nonce. Falls back to CLIENT_SECRET.
const STATE_SECRET = process.env.STATE_SECRET || CLIENT_SECRET;

const app = express();

// ── HMAC helpers ─────────────────────────────────────────────────────────────

/**
 * Verify the HMAC on the OAuth redirect query string.
 * Shopify sends this as a hex string in the `hmac` query param.
 */
function verifyOAuthHmac(query) {
  const { hmac, ...rest } = query;
  if (!hmac) return false;
  const message = Object.entries(rest)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join('&');
  const digest = crypto
    .createHmac('sha256', CLIENT_SECRET)
    .update(message)
    .digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmac));
  } catch {
    return false;
  }
}

/**
 * Verify the HMAC on an incoming webhook.
 * Shopify sends this as a base64 string in the X-Shopify-Hmac-Sha256 header.
 * Requires the raw (unparsed) request body.
 */
function verifyWebhookHmac(rawBody, hmacHeader) {
  if (!hmacHeader) return false;
  const digest = crypto
    .createHmac('sha256', CLIENT_SECRET)
    .update(rawBody)
    .digest('base64');
  try {
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmacHeader));
  } catch {
    return false;
  }
}

// ── OAuth state (signed nonce — no DB required) ───────────────────────────────

/**
 * Generate a short-lived, signed state token embedding the shop domain.
 * Format (base64url): shop:timestamp:hmac
 */
function generateState(shop) {
  const ts = Date.now();
  const payload = `${shop}:${ts}`;
  const sig = crypto
    .createHmac('sha256', STATE_SECRET)
    .update(payload)
    .digest('hex');
  return Buffer.from(`${payload}:${sig}`).toString('base64url');
}

/**
 * Validate the state token returned by Shopify.
 * Checks the signature and that the token is no older than 5 minutes.
 */
function validateState(state, shop) {
  try {
    const decoded = Buffer.from(state, 'base64url').toString();
    const parts = decoded.split(':');
    // parts: [shop, timestamp, sig]  (shop may contain dots but no colons)
    const sig = parts.pop();
    const ts = parts.pop();
    const statShop = parts.join(':');

    if (statShop !== shop) return false;
    if (Date.now() - parseInt(ts, 10) > 5 * 60 * 1000) return false; // 5-min window

    const expected = crypto
      .createHmac('sha256', STATE_SECRET)
      .update(`${statShop}:${ts}`)
      .digest('hex');
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
  } catch {
    return false;
  }
}

// ── Middleware ────────────────────────────────────────────────────────────────

// Webhook routes need the raw body for HMAC verification — mount before json middleware.
app.use('/webhooks', express.raw({ type: 'application/json' }));

// Everything else can use parsed JSON.
app.use(express.json());

// ── App pages ─────────────────────────────────────────────────────────────────

app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Galaxy Bundle Discount</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 60px auto; padding: 0 20px; color: #333; }
    h1 { color: #5c2d91; }
    .tier { background: #f5f0ff; border-left: 4px solid #5c2d91; padding: 12px 16px; margin: 10px 0; border-radius: 4px; }
    .badge { display: inline-block; background: #00875a; color: white; padding: 4px 14px; border-radius: 20px; font-size: 14px; margin-bottom: 20px; }
    p.note { color: #888; font-size: 14px; margin-top: 40px; }
  </style>
</head>
<body>
  <h1>Galaxy Bundle Discount</h1>
  <span class="badge">Active</span>
  <p>Automatically applies tiered discounts to galaxy edible image sets based on total topper count across all items in the cart. No coupon code needed.</p>
  <h2>Discount Tiers</h2>
  <div class="tier"><strong>10% off</strong> &mdash; 24 to 35 toppers</div>
  <div class="tier"><strong>15% off</strong> &mdash; 36 to 47 toppers</div>
  <div class="tier"><strong>20% off</strong> &mdash; 48 or more toppers</div>
  <p class="note">Discounts are applied automatically at checkout. Manage discounts in your <a href="https://admin.shopify.com/discounts">Shopify Admin &rarr; Discounts</a>.</p>
</body>
</html>`);
});

app.get('/privacy', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Privacy Policy &mdash; Galaxy Bundle Discount</title>
  <style>body { font-family: sans-serif; max-width: 700px; margin: 40px auto; padding: 0 20px; line-height: 1.6; }</style>
</head>
<body>
  <h1>Privacy Policy</h1>
  <p>Last updated: April 2026</p>
  <p>Galaxy Bundle Discount ("the App") is built and maintained by Practical Home Robotics LLC.</p>
  <h2>Data Collection</h2>
  <p>The App does not collect, store, or share any personal data. The App accesses only the minimum store data required to apply automatic bundle discounts (cart line item quantities and product attributes).</p>
  <h2>Data Use</h2>
  <p>Cart data is processed transiently by a Shopify Function to calculate discount eligibility. No data is retained after the calculation is complete.</p>
  <h2>Third Parties</h2>
  <p>The App does not share any data with third parties.</p>
  <h2>Contact</h2>
  <p>For questions, contact: j99441835@gmail.com</p>
</body>
</html>`);
});

// ── OAuth ─────────────────────────────────────────────────────────────────────

app.get('/auth', (req, res) => {
  const shop = req.query.shop || '';
  if (!shop) return res.status(400).send('Missing shop parameter');

  const state = generateState(shop);
  const redirectUri = `${APP_URL}/auth/callback`;
  const url =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${CLIENT_ID}` +
    `&scope=${SCOPES}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${state}`;

  res.redirect(url);
});

app.get('/auth/callback', async (req, res) => {
  // 1. Verify OAuth HMAC
  if (!verifyOAuthHmac(req.query)) {
    return res.status(403).send('HMAC verification failed');
  }

  const { code, shop, state } = req.query;

  // 2. Verify state nonce
  if (!validateState(state, shop)) {
    return res.status(403).send('Invalid or expired state parameter');
  }

  // 3. Exchange code for access token
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    code,
  });
  const tokenRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });
  const tokenData = await tokenRes.json();
  const { access_token, error } = tokenData;

  if (error || !access_token) {
    return res.status(500).send('Install failed: ' + JSON.stringify(tokenData));
  }

  // 4. Find the Galaxy Bundle Discount function installed on this shop
  const fnQuery = `{
    shopifyFunctions(first: 25) {
      nodes { id title apiType }
    }
  }`;
  const fnRes = await fetch(`https://${shop}/admin/api/2026-01/graphql.json`, {
    method: 'POST',
    headers: {
      'X-Shopify-Access-Token': access_token,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ query: fnQuery }),
  });
  const fnData = await fnRes.json();
  const fn = fnData.data?.shopifyFunctions?.nodes?.find(
    (n) => n.title === 'Galaxy Bundle Discount' && n.apiType === 'product_discounts'
  );

  if (!fn) {
    return res.status(500).send(
      `<pre>Could not find Galaxy Bundle Discount function.\nAll functions:\n${JSON.stringify(fnData, null, 2)}</pre>`
    );
  }

  // 5. Idempotency: check if the discount already exists before creating it
  const existingQuery = `{
    automaticDiscountNodes(first: 50) {
      nodes {
        id
        automaticDiscount {
          ... on DiscountAutomaticApp {
            title
            status
          }
        }
      }
    }
  }`;
  const existingRes = await fetch(`https://${shop}/admin/api/2026-01/graphql.json`, {
    method: 'POST',
    headers: {
      'X-Shopify-Access-Token': access_token,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ query: existingQuery }),
  });
  const existingData = await existingRes.json();
  const alreadyExists = existingData.data?.automaticDiscountNodes?.nodes?.some(
    (n) => n.automaticDiscount?.title === 'Galaxy Bundle Discount'
  );

  if (alreadyExists) {
    console.log('Galaxy Bundle Discount already exists for shop:', shop);
    return res.redirect(`${APP_URL}/`);
  }

  // 6. Create the automatic discount
  const mutation = `mutation {
    discountAutomaticAppCreate(automaticAppDiscount: {
      title: "Galaxy Bundle Discount"
      functionId: "${fn.id}"
      startsAt: "2026-04-01T00:00:00Z"
    }) {
      automaticAppDiscount { discountId title status }
      userErrors { field message }
    }
  }`;

  const gqlRes = await fetch(`https://${shop}/admin/api/2026-01/graphql.json`, {
    method: 'POST',
    headers: {
      'X-Shopify-Access-Token': access_token,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ query: mutation }),
  });
  const result = await gqlRes.json();
  console.log('discountAutomaticAppCreate result:', JSON.stringify(result, null, 2));

  const userErrors = result.data?.discountAutomaticAppCreate?.userErrors;
  const discount = result.data?.discountAutomaticAppCreate?.automaticAppDiscount;

  if (userErrors?.length > 0) {
    return res.status(500).send(
      `<pre>Discount creation error:\n${JSON.stringify(userErrors, null, 2)}\n\nFunction ID: ${fn.id}\n\nFull result:\n${JSON.stringify(result, null, 2)}</pre>`
    );
  }

  if (!discount) {
    return res.status(500).send(
      `<pre>Unexpected response:\n${JSON.stringify(result, null, 2)}</pre>`
    );
  }

  res.redirect(`${APP_URL}/`);
});

// ── Webhooks ──────────────────────────────────────────────────────────────────

/**
 * Helper: authenticate an incoming webhook and send 200, or reject with 401.
 * Returns true if verified (caller should return after calling this).
 */
function handleWebhook(req, res, onVerified) {
  if (!verifyWebhookHmac(req.body, req.headers['x-shopify-hmac-sha256'])) {
    return res.status(401).send('Unauthorized');
  }
  onVerified();
  res.status(200).send('OK');
}

// GDPR — customer data request
// Shopify asks: "what data do you have on this customer?"
// We store nothing, so we acknowledge and move on.
app.post('/webhooks/customers/data_request', (req, res) => {
  handleWebhook(req, res, () => {
    console.log('customers/data_request received — no data stored');
  });
});

// GDPR — erase customer data
// We store nothing, so nothing to delete.
app.post('/webhooks/customers/redact', (req, res) => {
  handleWebhook(req, res, () => {
    console.log('customers/redact received — no data stored');
  });
});

// GDPR — erase shop data (merchant uninstalled 48+ hours ago)
// We store nothing, so nothing to delete.
app.post('/webhooks/shop/redact', (req, res) => {
  handleWebhook(req, res, () => {
    console.log('shop/redact received — no data stored');
  });
});

// App uninstalled
// The discount was created inside the merchant's own store, so Shopify cleans it
// up automatically. Nothing extra needed here.
app.post('/webhooks/app/uninstalled', (req, res) => {
  handleWebhook(req, res, () => {
    const body = JSON.parse(req.body.toString());
    console.log('app/uninstalled for shop:', body.domain);
  });
});

module.exports = app;
