const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const app = express();

const CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const HOST = process.env.HOST;

const SCOPES = 'read_orders,write_orders,read_products,write_products,read_customers,write_customers,read_inventory,write_inventory,read_fulfillments,write_fulfillments,read_shopify_payments_payouts,read_shopify_payments_accounts,read_shopify_payments_disputes,write_shopify_payments_disputes,read_analytics,read_reports,write_reports,read_discounts,write_discounts,read_draft_orders,write_draft_orders,read_gift_cards,write_gift_cards,read_locations,write_locations,read_markets,write_markets,read_metaobjects,write_metaobjects,read_themes,write_themes,read_translations,write_translations,read_content,write_content,read_files,write_files,read_price_rules,write_price_rules,read_publications,write_publications,read_script_tags,write_script_tags,read_shipping,write_shipping,read_purchase_options,write_purchase_options';

app.get('/auth', (req, res) => {
  const shop = req.query.shop;
  if (!shop) return res.send('Missing ?shop=');
  const state = crypto.randomBytes(16).toString('hex');
  const redirectUri = HOST + '/auth/callback';
  const url = 'https://' + shop + '/admin/oauth/authorize?client_id=' + CLIENT_ID + '&scope=' + SCOPES + '&redirect_uri=' + encodeURIComponent(redirectUri) + '&state=' + state;
  res.redirect(url);
});

app.get('/auth/callback', async (req, res) => {
  const { shop, code, hmac } = req.query;
  if (!shop || !code) return res.status(400).send('Missing params');
  const params = Object.assign({}, req.query);
  delete params.hmac;
  const msg = Object.keys(params).sort().map(k => k + '=' + params[k]).join('&');
  const sig = crypto.createHmac('sha256', CLIENT_SECRET).update(msg).digest('hex');
  if (sig !== hmac) return res.status(403).send('Invalid HMAC');
  try {
    const r = await axios.post('https://' + shop + '/admin/oauth/access_token', {
      client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code
    });
    const token = r.data.access_token;
    console.log('JARVIS TOKEN: ' + token);
    res.send('<html><body style="background:#0f0f0f;color:#fff;font-family:sans-serif;padding:40px;max-width:700px;margin:auto"><h1 style="color:#00ff88">Jarvis has full Shopify access</h1><p>Store: <b>' + shop + '</b></p><p>Copy this token into Jarvis as <code>SHOPIFY_ACCESS_TOKEN</code>:</p><div id=t style="background:#111;padding:20px;border-radius:8px;font-family:monospace;font-size:13px;color:#00ff88;word-break:break-all">' + token + '</div><button onclick="navigator.clipboard.writeText(document.getElementById('t').textContent).then(()=>this.textContent='Copied!')" style="margin-top:16px;background:#00ff88;color:#000;border:none;padding:12px 24px;border-radius:6px;cursor:pointer;font-weight:bold;font-size:15px">Copy Token</button></body></html>');
  } catch(e) {
    res.status(500).send('Error: ' + JSON.stringify(e.response && e.response.data));
  }
});

app.get('/', (req, res) => res.send('Jarvis Shopify Auth - OK'));
app.listen(process.env.PORT || 3000);
