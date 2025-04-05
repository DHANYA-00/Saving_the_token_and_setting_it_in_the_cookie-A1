const jwt = require('jsonwebtoken');
const crypto = require('crypto');


const JWT_SECRET = 'my_jwt_secret'; // Used to sign the JWT
const ENCRYPTION_KEY = crypto.randomBytes(32); // 256-bit key
const IV_LENGTH = 16; // AES block size

const encryptPayload = (payload) => {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(JSON.stringify(payload), 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return iv.toString('base64') + ':' + encrypted;
};

const decryptPayload = (encrypted) => {
  const [ivStr, data] = encrypted.split(':');
  const iv = Buffer.from(ivStr, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(data, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
};

const encrypt = (payload) => {
  const encryptedPayload = encryptPayload(payload);
  const token = jwt.sign({ data: encryptedPayload }, JWT_SECRET, { expiresIn: '1h' });
  return token;
};

const decrypt = (token) => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const decryptedPayload = decryptPayload(decoded.data);
    console.log('Success:', decryptedPayload);
    return decryptedPayload;
  } catch (err) {
    console.error('Decryption failed:', err.message);
    return null;
  }
};

module.exports = {
  encrypt,
  decrypt
};

const payload = { userId: 123, role: 'admin' };

const token = encrypt(payload);
console.log('Encrypted JWT:', token);

const result = decrypt(token);
console.log('Decrypted Payload:', result);

