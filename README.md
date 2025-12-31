# Secure API Key Server

A Node.js Express server that securely exposes API keys using encrypted date-based authentication.

## Security Mechanism

The server validates requests using a time-based encrypted header:

1. Client generates current date in YYYYMMDD format
2. Client encrypts the date using AES encryption with a shared secret key
3. Client sends encrypted date in `x-secure-date` header
4. Server decrypts the header and validates the date matches current date (±1 day tolerance for timezone differences)
5. If valid, server returns the API keys; otherwise returns 403 Forbidden

## Setup

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment Variables

Create a `.env` file based on `.env.example`:

```bash
cp .env.example .env
```

Edit `.env` and set your values:

```env
PORT=3000
SHARED_SECRET_KEY=your-super-secret-key-here-change-me
API_KEY_1=your-first-api-key-here
API_KEY_2=your-second-api-key-here
API_KEY_3=your-third-api-key-here
```

**Important**: Use a strong, random string for `SHARED_SECRET_KEY` (minimum 16 characters recommended).

### 3. Start the Server

```bash
npm start
```

The server will run on `http://localhost:3000` (or your configured PORT).

## API Endpoints

### GET /api/get-keys

Returns your API keys if the security header is valid.

**Headers:**
- `x-secure-date`: Encrypted current date (YYYYMMDD format)

**Success Response (200):**
```json
{
  "success": true,
  "keys": {
    "apiKey1": "your-api-key-1",
    "apiKey2": "your-api-key-2",
    "apiKey3": "your-api-key-3"
  }
}
```

**Error Responses:**
- 403 Forbidden: Invalid or missing security header
- 500 Internal Server Error: Server configuration error

### GET /health

Health check endpoint.

**Success Response (200):**
```json
{
  "status": "ok",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

## Client Implementation

### JavaScript (Node.js)

See `client-helper.js` for a complete Node.js example.

```javascript
const CryptoJS = require('crypto-js');

function getCurrentDateString() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  return `${year}${month}${day}`;
}

function generateSecureHeader(secretKey) {
  const currentDate = getCurrentDateString();
  const encrypted = CryptoJS.AES.encrypt(currentDate, secretKey).toString();
  return encrypted;
}

async function fetchApiKeys(serverUrl, secretKey) {
  const secureHeader = generateSecureHeader(secretKey);

  const response = await fetch(`${serverUrl}/api/get-keys`, {
    method: 'GET',
    headers: {
      'x-secure-date': secureHeader,
      'Content-Type': 'application/json'
    }
  });

  const data = await response.json();
  return data.keys;
}
```

### JavaScript (Browser)

See `client-helper-browser.js` for a browser-compatible example.

First, include CryptoJS in your HTML:

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js"></script>
<script src="client-helper-browser.js"></script>
```

### Dart/Flutter

See `client_helper.dart` for a complete Dart example.

**Required packages** (add to `pubspec.yaml`):
```yaml
dependencies:
  encrypt: ^5.0.3
  http: ^1.1.0
```

```dart
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:http/http.dart' as http;

String generateSecureHeader(String secretKey) {
  final now = DateTime.now();
  final currentDate = '${now.year}${now.month.toString().padLeft(2, '0')}${now.day.toString().padLeft(2, '0')}';

  final key = encrypt.Key.fromUtf8(secretKey.padRight(32).substring(0, 32));
  final iv = encrypt.IV.fromLength(16);
  final encrypter = encrypt.Encrypter(encrypt.AES(key));

  return encrypter.encrypt(currentDate, iv: iv).base64;
}
```

## Security Considerations

1. **Shared Secret**: Keep `SHARED_SECRET_KEY` confidential and identical on both server and client
2. **HTTPS**: Always use HTTPS in production to prevent header interception
3. **Time Sync**: Ensure server and client clocks are reasonably synchronized
4. **Key Rotation**: Consider rotating your shared secret periodically
5. **Environment Variables**: Never commit `.env` files to version control

## Testing

Test the health endpoint:
```bash
curl http://localhost:3000/health
```

Test with a valid encrypted header (requires generating the header first):
```bash
node client-helper.js
```

## License

MIT
