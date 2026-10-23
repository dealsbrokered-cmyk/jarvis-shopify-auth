const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const app = express();

const CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const SCOPES = process.env.SHOPIFY_SCOPES || 'read_analytics,write_analytics_annotations,read_app_proxy,write_app_proxy,read_assigned_fulfillment_orders,write_assigned_fulfillment_orders,read_audit_events,read_customer_events,read_cart_transforms,write_cart_transforms,read_validations,write_validations,read_cash_tracking,write_cash_tracking,read_channels,write_channels,read_checkout_and_accounts_configurations,write_checkout_and_accounts_configurations,read_checkout_branding_settings,write_checkout_branding_settings,write_checkouts,read_checkouts,read_companies,write_companies,read_custom_fulfillment_services,write_custom_fulfillment_services,read_custom_pixels,write_custom_pixels,read_customers,write_customers,read_customer_data_erasure,write_customer_data_erasure,read_customer_merge,write_customer_merge,read_delivery_customizations,write_delivery_customizations,read_price_rules,write_price_rules,read_discounts,write_discounts,write_draft_orders,read_draft_orders,read_files,write_files,read_fulfillments,write_fulfillments,read_gift_cards,write_gift_cards,write_inventory,read_inventory,read_legal_policies,write_legal_policies,read_locales,write_locales,write_locations,read_locations,write_marketing_events,read_marketing_events,read_markets,write_markets,read_metaobject_definitions,write_metaobject_definitions,read_metaobjects,write_metaobjects,read_online_store_pages,write_online_store_pages,write_order_edits,read_order_edits,read_orders,write_orders,read_payment_terms,write_payment_terms,read_payment_customizations,write_payment_customizations,read_products,write_products,read_publications,write_publications,read_purchase_options,write_purchase_options,write_reports,read_reports,read_resource_feedbacks,write_resource_feedbacks,write_returns,read_script_tags,write_script_tags,read_shopify_payments_accounts,read_shopify_payments_payouts,read_shopify_payments_disputes,write_shopify_payments_disputes,read_content,write_content,read_themes,write_themes,read_translations,write_translations';
const HOST = process.env.HOST;

let accessTokenStore = {};

app.get('/auth', (req, res) => {
  const shop = req.query.shop;
  if (!shop) return res.send('Missing ?shop= parameter');
  const state = crypto.randomBytes(16).toString('hex');
  const redirectUri = `${HOST}/auth/callback`;
  const installUrl = `https://${shop}/admin/oauth/authorize?client_id=${CLIENT_ID}&scope=${SCOPES}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`;
  res.redirect(installUrl);
});

app.get('/auth/callback', async (req, res) => {
  const { shop, code, hmac, state } = req.query;
  if (!shop || !code) return res.status(400).send('Missing parameters');
  const queryParams = Object.assign({}, req.query);
  delete queryParams.hmac;
  const message = Object.keys(queryParams).sort().map(k => `${k}=${queryParams[k]}`).join('&');
  const digest = crypto.createHmac('sha256', CLIENT_SECRET).update(message).digest('hex');
  if (digest !== hmac) return res.status(403).send('HMAC validation failed');
  try {
    const response = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
    });
    const token = response.data.access_token;
    accessTokenStore[shop] = token;
    console.log('\n========================================');
    console.log('✅ ACCESS TOKEN OBTAINED FOR JARVIS');
    console.log(`SHOP: ${shop}`);
    console.log(`TOKEN: ${token}`);
    console.log('========================================\n');
    res.send(`<!DOCTYPE html><html><head><title>Jarvis Shopify Auth</title><style>body{font-family:sans-serif;max-width:600px;margin:60px auto;padding:20px;background:#0f0f0f;color:#fff}.token-box{background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:20px;margin:20px 0;word-break:break-all;font-family:monospace;font-size:14px;color:#00ff88}h1{color:#00ff88}p{color:#aaa}.copy-btn{background:#00ff88;color:#000;border:none;padding:10px 20px;border-radius:6px;cursor:pointer;font-weight:bold;margin-top:10px}</style></head><body><h1>✅ Jarvis has full Shopify access</h1><p>Store: <strong>${shop}</strong></p><p>Copy this token and add it to your Jarvis config as <code>SHOPIFY_ACCESS_TOKEN</code>:</p><div class="token-box" id="token">${token}</div><button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('token').textContent).then(()=>this.textContent='Copied!')">Copy Token</button><p style="margin-top:30px;font-size:12px;color:#555">Keep this token secret. It gives full access to your Shopify store.</p></body></html>`);
  } catch (err) {
    console.error('Token exchange failed:', err.response?.data || err.message);
    res.status(500).send('Failed to get access token: ' + JSON.stringify(err.response?.data));
  }
});

app.get('/', (req, res) => {
  res.send('Jarvis Shopify Auth — visit /auth?shop=your-store.myshopify.com to install');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Jarvis Shopify Auth running on port ${PORT}`));
