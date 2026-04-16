const express = require('express');
const crypto = require('crypto');

const CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const FUNCTION_ID = process.env.FUNCTION_ID;
const APP_URL = process.env.APP_URL;
const SCOPES = 'write_discounts';

const app = express();

function verifyHmac(query) {
  const { hmac, ...rest } = query;
  if (!hmac) return false;
  const message = Object.entries(rest)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join('&');
  const digest = crypto.createHmac('sha256', CLIENT_SECRET).update(message).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmac));
}

// App home
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
  <h1>🪐 Galaxy Bundle Discount</h1>
  <span class="badge">✓ Active</span>
  <p>Automatically applies tiered discounts to galaxy edible image sets based on total topper count across all items in the cart. No coupon code needed.</p>
  <h2>Discount Tiers</h2>
  <div class="tier"><strong>10% off</strong> &mdash; 24 to 35 toppers</div>
  <div class="tier"><strong>15% off</strong> &mdash; 36 to 47 toppers</div>
  <div class="tier"><strong>20% off</strong> &mdash; 48 or more toppers</div>
  <p class="note">Discounts are applied automatically at checkout. Manage discounts in <a href="https://admin.shopify.com/store/edibleimagesmi/discounts">Shopify Admin → Discounts</a>.</p>
</body>
</html>`);
});

// Privacy policy
app.get('/privacy', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Privacy Policy — Galaxy Bundle Discount</title>
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

// OAuth start
app.get('/auth', (req, res) => {
  const shop = req.query.shop || '';
  if (!shop) return res.status(400).send('Missing shop parameter');
  const redirectUri = `${APP_URL}/auth/callback`;
  const url = `https://${shop}/admin/oauth/authorize?client_id=${CLIENT_ID}&scope=${SCOPES}&redirect_uri=${encodeURIComponent(redirectUri)}&state=galaxy-bundle`;
  res.redirect(url);
});

// OAuth callback — exchanges code, creates discount, redirects to app home
app.get('/auth/callback', async (req, res) => {
  if (!verifyHmac(req.query)) {
    return res.status(403).send('HMAC verification failed');
  }

  const { code, shop } = req.query;

  // Exchange code for access token
  const params = new URLSearchParams({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code });
  const tokenRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });
  const tokenData = await tokenRes.json();
  const { access_token, error } = tokenData;

  if (error || !access_token) {
    return res.send('Install failed: ' + JSON.stringify(tokenData));
  }

  // Create the automatic discount
  const mutation = `mutation {
    discountAutomaticAppCreate(automaticAppDiscount: {
      title: "Galaxy Bundle Discount"
      functionId: "${FUNCTION_ID}"
      startsAt: "2026-04-01T00:00:00Z"
    }) {
      automaticAppDiscount { discountId title status }
      userErrors { field message }
    }
  }`;

  const gqlRes = await fetch(`https://${shop}/admin/api/2026-01/graphql.json`, {
    method: 'POST',
    headers: { 'X-Shopify-Access-Token': access_token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: mutation }),
  });
  const result = await gqlRes.json();
  const userErrors = result.data?.discountAutomaticAppCreate?.userErrors;

  if (userErrors?.length > 0) {
    return res.send('Discount creation error: ' + JSON.stringify(userErrors));
  }

  res.redirect(`${APP_URL}/`);
});

module.exports = app;
