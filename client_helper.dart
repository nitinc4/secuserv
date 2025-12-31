import 'dart:convert';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:http/http.dart' as http;

String getCurrentDateString() {
  final now = DateTime.now();
  final year = now.year.toString();
  final month = now.month.toString().padLeft(2, '0');
  final day = now.day.toString().padLeft(2, '0');
  return '$year$month$day';
}

String generateSecureHeader(String secretKey) {
  final currentDate = getCurrentDateString();

  final key = encrypt.Key.fromUtf8(secretKey.padRight(32).substring(0, 32));
  final iv = encrypt.IV.fromLength(16);

  final encrypter = encrypt.Encrypter(encrypt.AES(key));
  final encrypted = encrypter.encrypt(currentDate, iv: iv);

  return encrypted.base64;
}

Future<Map<String, dynamic>> fetchApiKeys(String serverUrl, String secretKey) async {
  final secureHeader = generateSecureHeader(secretKey);

  try {
    final response = await http.get(
      Uri.parse('$serverUrl/api/get-keys'),
      headers: {
        'x-secure-date': secureHeader,
        'Content-Type': 'application/json',
      },
    );

    if (response.statusCode != 200) {
      final errorData = jsonDecode(response.body);
      throw Exception(errorData['message'] ?? 'Failed to fetch API keys');
    }

    final data = jsonDecode(response.body);
    return data['keys'];
  } catch (error) {
    print('Error fetching API keys: $error');
    rethrow;
  }
}

void main() async {
  const sharedSecret = 'your-super-secret-key-here-change-me';
  const serverUrl = 'http://localhost:3000';

  try {
    final keys = await fetchApiKeys(serverUrl, sharedSecret);
    print('Successfully retrieved API keys: $keys');
  } catch (error) {
    print('Failed to retrieve API keys: $error');
  }
}
