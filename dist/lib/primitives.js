"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateUserSecretKey = exports.validateUserPublicKey = exports.generateUserKeyPair = exports.crypto_box_seal_open = exports.crypto_box_seal = exports.hash = exports.extractEncryptionKey = exports.generateEncryptionKey = exports.decryptBlockStream = exports.encryptBlockStream = exports.decryptBlob = exports.encryptBlob = void 0;
const sodium_native_1 = __importDefault(require("sodium-native"));
/**
 * XChaCha20 encryption, automatically generates a random nonce (192 Bit) and prepends it to the ciphtertext
 * @param {Buffer} plaintext
 * @param {Buffer} key
 * @returns {Buffer}
 */
function encryptBlob(plaintext, key) {
    const nonce = Buffer.allocUnsafe(sodium_native_1.default.crypto_stream_NONCEBYTES);
    sodium_native_1.default.randombytes_buf(nonce);
    const ciphertext = Buffer.allocUnsafe(sodium_native_1.default.crypto_stream_NONCEBYTES + plaintext.length);
    nonce.copy(ciphertext);
    sodium_native_1.default.crypto_stream_xor(ciphertext.slice(sodium_native_1.default.crypto_stream_NONCEBYTES), plaintext, nonce, key);
    return ciphertext;
}
exports.encryptBlob = encryptBlob;
/**
 * @param {Buffer} ciphertext
 * @param {Buffer} key
 * @returns {Buffer}
 */
function decryptBlob(ciphertext, key) {
    const nonce = ciphertext.slice(0, sodium_native_1.default.crypto_stream_NONCEBYTES);
    const plaintext = Buffer.allocUnsafe(ciphertext.length - sodium_native_1.default.crypto_stream_NONCEBYTES);
    sodium_native_1.default.crypto_stream_xor(plaintext, ciphertext.slice(sodium_native_1.default.crypto_stream_NONCEBYTES), nonce, key);
    return plaintext;
}
exports.decryptBlob = decryptBlob;
/**
 * ChaCha20 encryption for random access to a block stream, uses the index as nonce.
 * Use ONLY when it is guaranteed that the (key,nonce) combination is only used once (e.g. for a hypercore)!
 * @param {Buffer} plaintext data to encrypt
 * @param {number} index
 * @param {Buffer} key
 * @returns {Buffer}
 */
function encryptBlockStream(plaintext, index, key) {
    const ciphertext = Buffer.allocUnsafe(plaintext.length);
    const nonce = Buffer.alloc(sodium_native_1.default.crypto_stream_chacha20_NONCEBYTES);
    nonce.writeBigUInt64LE(BigInt(index));
    sodium_native_1.default.crypto_stream_chacha20_xor(ciphertext, plaintext, nonce, key);
    return ciphertext;
}
exports.encryptBlockStream = encryptBlockStream;
/**
 * @param {Buffer} ciphertext
 * @param {number} index
 * @param {Buffer} key of length sodium.crypto_stream_chacha20_KEYBYTES
 * @returns {Buffer}
 */
function decryptBlockStream(ciphertext, index, key) {
    const plaintext = Buffer.allocUnsafe(ciphertext.length);
    const nonce = Buffer.alloc(sodium_native_1.default.crypto_stream_chacha20_NONCEBYTES);
    nonce.writeBigUInt64LE(BigInt(index));
    sodium_native_1.default.crypto_stream_chacha20_xor(plaintext, ciphertext, nonce, key);
    return plaintext;
}
exports.decryptBlockStream = decryptBlockStream;
/**
 * @returns {import('sodium-native').SecureBuffer}
 */
function generateEncryptionKey() {
    const key = sodium_native_1.default.sodium_malloc(sodium_native_1.default.crypto_stream_KEYBYTES);
    sodium_native_1.default.randombytes_buf(key);
    return key;
}
exports.generateEncryptionKey = generateEncryptionKey;
/**
 * Copies the buffer to a memory-protected buffer and zeroes out the original one
 * @param {Buffer} buf
 * @returns {import('sodium-native').SecureBuffer}
 */
function extractEncryptionKey(buf) {
    if (!Buffer.isBuffer(buf)) {
        throw new Error('key is not an instance of Buffer');
    }
    if (buf.length !== sodium_native_1.default.crypto_stream_KEYBYTES) {
        throw new Error('key has invalid length');
    }
    const key = sodium_native_1.default.sodium_malloc(sodium_native_1.default.crypto_stream_KEYBYTES);
    buf.copy(key);
    buf.fill(0);
    return key;
}
exports.extractEncryptionKey = extractEncryptionKey;
/**
 * @param {Buffer|string} buf
 */
function hash(buf) {
    if (!Buffer.isBuffer(buf)) {
        buf = Buffer.from(buf);
    }
    const out = Buffer.allocUnsafe(sodium_native_1.default.crypto_generichash_BYTES);
    sodium_native_1.default.crypto_generichash(out, buf);
    return out;
}
exports.hash = hash;
function crypto_box_seal(pubkey, message) {
    if (!Buffer.isBuffer(pubkey) || pubkey.length !== sodium_native_1.default.crypto_box_PUBLICKEYBYTES) {
        throw new Error('invalid public key: ' + (pubkey === null || pubkey === void 0 ? void 0 : pubkey.toString()));
    }
    const ciphertext = Buffer.allocUnsafe(sodium_native_1.default.crypto_box_SEALBYTES + message.length);
    sodium_native_1.default.crypto_box_seal(ciphertext, message, pubkey);
    return ciphertext;
}
exports.crypto_box_seal = crypto_box_seal;
function crypto_box_seal_open(pubkey, secretkey, ciphertext) {
    if (!Buffer.isBuffer(pubkey) || pubkey.length !== sodium_native_1.default.crypto_box_PUBLICKEYBYTES) {
        throw new Error('invalid public key: ' + (pubkey === null || pubkey === void 0 ? void 0 : pubkey.toString()));
    }
    if (!Buffer.isBuffer(secretkey) || secretkey.length !== sodium_native_1.default.crypto_box_SECRETKEYBYTES) {
        throw new Error('invalid secret key!');
    }
    const message = Buffer.allocUnsafe(ciphertext.length - sodium_native_1.default.crypto_box_SEALBYTES);
    if (sodium_native_1.default.crypto_box_seal_open(message, ciphertext, pubkey, secretkey) !== 0) {
        return null;
    }
    else {
        return message;
    }
}
exports.crypto_box_seal_open = crypto_box_seal_open;
function generateUserKeyPair() {
    const pubkey = Buffer.allocUnsafe(sodium_native_1.default.crypto_box_PUBLICKEYBYTES);
    const secretkey = Buffer.allocUnsafe(sodium_native_1.default.crypto_box_SECRETKEYBYTES);
    sodium_native_1.default.crypto_box_keypair(pubkey, secretkey);
    return { pubkey, secretkey };
}
exports.generateUserKeyPair = generateUserKeyPair;
function validateUserPublicKey(key) {
    return Buffer.isBuffer(key) && key.length === sodium_native_1.default.crypto_box_PUBLICKEYBYTES;
}
exports.validateUserPublicKey = validateUserPublicKey;
function validateUserSecretKey(key) {
    return Buffer.isBuffer(key) && key.length === sodium_native_1.default.crypto_box_SECRETKEYBYTES;
}
exports.validateUserSecretKey = validateUserSecretKey;
//# sourceMappingURL=primitives.js.map