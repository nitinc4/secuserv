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

  try {
    const response = await fetch(`${serverUrl}/api/get-keys`, {
      method: 'GET',
      headers: {
        'x-secure-date': secureHeader,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.message || 'Failed to fetch API keys');
    }

    const data = await response.json();
    return data.keys;
  } catch (error) {
    console.error('Error fetching API keys:', error);
    throw error;
  }
}

const SHARED_SECRET = 'your-super-secret-key-here-change-me';
const SERVER_URL = 'http://localhost:3000';

fetchApiKeys(SERVER_URL, SHARED_SECRET)
  .then(keys => {
    console.log('Successfully retrieved API keys:', keys);
  })
  .catch(error => {
    console.error('Failed to retrieve API keys:', error.message);
  });
