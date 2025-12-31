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

// Helper to get date string with optional day offset
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
    if (!encryptedData.includes(':')) return null;

    const parts = encryptedData.split(':');
    const ivString = parts[0];
    const ciphertext = parts[1];

    // Use the Date String (padded) as the Key
    const keyBytes = CryptoJS.enc.Utf8.parse(dateString.padEnd(32, ' ').substring(0, 32));
    const ivBytes = CryptoJS.enc.Base64.parse(ivString);

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

  // Return your actual keys here
  const apiKeys = {
    apiKey1: process.env.API_KEY_1,
    apiKey2: process.env.API_KEY_2,
    apiKey3: process.env.API_KEY_3,
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