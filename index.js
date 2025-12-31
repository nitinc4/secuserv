require('dotenv').config();
const express = require('express');
const cors = require('cors');
const CryptoJS = require('crypto-js');

const app = express();
const PORT = process.env.PORT || 3000;

// The fixed verification phrase both Client and Server must know
const VERIFICATION_PHRASE = "BNB_SECURE_ACCESS";

app.use(cors());
app.use(express.json());

// Helper to get date string with optional day offset (YYYYMMDD)
function getDateString(offsetDays = 0) {
  const date = new Date();
  date.setDate(date.getDate() + offsetDays);
  
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}${month}${day}`;
}

// Helper: Try to decrypt payload using a specific date string as the key
function tryDecryptWithDate(encryptedData, dateString) {
  try {
    // 1. Check format (IV:Ciphertext)
    if (!encryptedData || !encryptedData.includes(':')) return null;

    const parts = encryptedData.split(':');
    const ivString = parts[0];
    const ciphertext = parts[1];

    // 2. Use the Date String (padded to 32 bytes) as the Key
    const keyBytes = CryptoJS.enc.Utf8.parse(dateString.padEnd(32, ' ').substring(0, 32));
    const ivBytes = CryptoJS.enc.Base64.parse(ivString);

    // 3. Decrypt using AES-CBC
    const bytes = CryptoJS.AES.decrypt(ciphertext, keyBytes, {
      iv: ivBytes,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    });

    return bytes.toString(CryptoJS.enc.Utf8);
  } catch (error) {
    return null; 
  }
}

// --- NEW CONTROL LOGIC START ---

// 1. Global flag to control server availability (Default: true)
let isServerEnabled = true;

// 2. Command Endpoint to DISABLE requests
app.post('/admin/disable', (req, res) => {
  isServerEnabled = false;
  console.log('COMMAND: Server disabled. All API requests will now be rejected.');
  res.json({ status: 'disabled', message: 'Server is now in maintenance mode.' });
});

// 3. Command Endpoint to ENABLE requests
app.post('/admin/enable', (req, res) => {
  isServerEnabled = true;
  console.log('COMMAND: Server enabled. Requests are now accepted.');
  res.json({ status: 'enabled', message: 'Server is now active.' });
});

// 4. Middleware to block requests when disabled
app.use((req, res, next) => {
  // Always allow access to the toggle endpoints and health check
  if (req.path.startsWith('/admin') || req.path === '/health') {
    return next();
  }

  if (!isServerEnabled) {
    return res.status(503).json({ 
      error: 'Service Unavailable', 
      message: 'The server has been temporarily disabled by an administrator.' 
    });
  }
  
  next();
});

// --- NEW CONTROL LOGIC END ---

app.get('/api/get-keys', (req, res) => {
  const encryptedHeader = req.headers['x-secure-date'];

  if (!encryptedHeader) {
    return res.status(403).json({ error: 'Forbidden', message: 'Security header missing' });
  }

  // Generate candidate keys (Yesterday, Today, Tomorrow) to handle Timezone differences
  const candidateDates = [
    getDateString(0),  // Today
    getDateString(-1), // Yesterday
    getDateString(1)   // Tomorrow
  ];

  let authorized = false;

  // Try to decrypt with each date. If any works, we are good.
  for (const dateKey of candidateDates) {
    const decrypted = tryDecryptWithDate(encryptedHeader, dateKey);
    if (decrypted === VERIFICATION_PHRASE) {
      authorized = true;
      break; 
    }
  }

  if (!authorized) {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Security validation failed (Invalid Date Key)'
    });
  }

  // Return the specific keys from your .env file
  const apiKeys = {
    magentoBaseUrl: process.env.MAGENTO_BASE_URL,
    consumerKey: process.env.CONSUMER_KEY,
    consumerSecret: process.env.CONSUMER_SECRET,
    accessToken: process.env.ACCESS_TOKEN,
    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET,
    geminiApiKey: process.env.GEMINI_API_KEY,
    rfqUrl: process.env.RFQ_URL,
    rfqToken: process.env.RFQ_TOKEN
  };

  return res.json({
    success: true,
    keys: apiKeys
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`Secure API server running on port ${PORT}`);
});