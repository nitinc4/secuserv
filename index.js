require('dotenv').config();
const express = require('express');
const cors = require('cors');
const CryptoJS = require('crypto-js');
const nodemailer = require('nodemailer'); // <--- 1. Import Nodemailer

const app = express();
const PORT = process.env.PORT || 3000;
const VERIFICATION_PHRASE = "BNB_SECURE_ACCESS";

app.use(cors());
app.use(express.json());

// --- 2. Configure Email Transporter ---
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: process.env.SMTP_PORT == 465, // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// Helper to get date string
function getDateString(offsetDays = 0) {
  const date = new Date();
  date.setDate(date.getDate() + offsetDays);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}${month}${day}`;
}

// Helper: Try to decrypt payload
function tryDecryptWithDate(encryptedData, dateString) {
  try {
    if (!encryptedData || !encryptedData.includes(':')) return null;
    const parts = encryptedData.split(':');
    const ivString = parts[0];
    const ciphertext = parts[1];
    const keyBytes = CryptoJS.enc.Utf8.parse(dateString.padEnd(32, ' ').substring(0, 32));
    const ivBytes = CryptoJS.enc.Base64.parse(ivString);
    const bytes = CryptoJS.AES.decrypt(ciphertext, keyBytes, {
      iv: ivBytes, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7
    });
    return bytes.toString(CryptoJS.enc.Utf8);
  } catch (error) { return null; }
}

// --- 3. Refactored Security Middleware ---
// This allows us to protect ANY route with your date-encryption logic
const verifySecureHeader = (req, res, next) => {
  const encryptedHeader = req.headers['x-secure-date'];

  if (!encryptedHeader) {
    return res.status(403).json({ error: 'Forbidden', message: 'Security header missing' });
  }

  const candidateDates = [getDateString(0), getDateString(-1), getDateString(1)];
  let authorized = false;

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
  
  next(); // Access granted
};

// --- Server Control Logic ---
let isServerEnabled = true;

app.post('/admin/disable', (req, res) => {
  isServerEnabled = false;
  console.log('COMMAND: Server disabled.');
  res.json({ status: 'disabled' });
});

app.post('/admin/enable', (req, res) => {
  isServerEnabled = true;
  console.log('COMMAND: Server enabled.');
  res.json({ status: 'enabled' });
});

app.use((req, res, next) => {
  if (req.path.startsWith('/admin') || req.path === '/health') return next();
  if (!isServerEnabled) return res.status(503).json({ error: 'Service Unavailable' });
  next();
});

// --- API Routes ---

// Updated: Now uses the verifySecureHeader middleware
app.get('/api/get-keys', verifySecureHeader, (req, res) => {
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
  return res.json({ success: true, keys: apiKeys });
});

// --- NEW: Email Sending Endpoint ---
app.post('/api/send-email', verifySecureHeader, async (req, res) => {
  const { to, subject, text, html } = req.body;

  if (!to || !subject || (!text && !html)) {
    return res.status(400).json({ error: 'Missing required fields (to, subject, text/html)' });
  }

  try {
    const info = await transporter.sendMail({
      from: process.env.SMTP_FROM, // Sender address
      to: to,                      // List of receivers
      subject: subject,            // Subject line
      text: text,                  // Plain text body
      html: html,                  // HTML body
    });

    console.log('Message sent: %s', info.messageId);
    res.json({ success: true, message: 'Email sent successfully', messageId: info.messageId });
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).json({ success: false, error: 'Failed to send email' });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`Secure API server running on port ${PORT}`);
});