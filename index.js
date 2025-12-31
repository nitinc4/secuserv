require('dotenv').config();
const express = require('express');
const cors = require('cors');
const CryptoJS = require('crypto-js');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

function getCurrentDateString() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  return `${year}${month}${day}`;
}

function decryptHeader(encryptedData, secretKey) {
  try {
    const bytes = CryptoJS.AES.decrypt(encryptedData, secretKey);
    const decryptedText = bytes.toString(CryptoJS.enc.Utf8);
    return decryptedText;
  } catch (error) {
    return null;
  }
}

function isDateValid(decryptedDate, allowedDifference = 1) {
  if (!decryptedDate || decryptedDate.length !== 8) {
    return false;
  }

  const currentDate = getCurrentDateString();

  if (decryptedDate === currentDate) {
    return true;
  }

  const decryptedDateObj = new Date(
    decryptedDate.substring(0, 4),
    parseInt(decryptedDate.substring(4, 6)) - 1,
    decryptedDate.substring(6, 8)
  );

  const currentDateObj = new Date(
    currentDate.substring(0, 4),
    parseInt(currentDate.substring(4, 6)) - 1,
    currentDate.substring(6, 8)
  );

  const diffTime = Math.abs(currentDateObj - decryptedDateObj);
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

  return diffDays <= allowedDifference;
}

app.get('/api/get-keys', (req, res) => {
  const encryptedHeader = req.headers['x-secure-date'];

  if (!encryptedHeader) {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Security header missing'
    });
  }

  const secretKey = process.env.SHARED_SECRET_KEY;

  if (!secretKey) {
    console.error('SHARED_SECRET_KEY not configured in environment variables');
    return res.status(500).json({
      error: 'Server configuration error'
    });
  }

  const decryptedDate = decryptHeader(encryptedHeader, secretKey);

  if (!decryptedDate) {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Invalid security header'
    });
  }

  if (!isDateValid(decryptedDate)) {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Security validation failed'
    });
  }

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
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`Secure endpoint: http://localhost:${PORT}/api/get-keys`);
});
