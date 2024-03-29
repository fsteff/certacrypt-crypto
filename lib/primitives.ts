import sodium from 'sodium-native'

/**
 * XChaCha20 encryption, automatically generates a random nonce (192 Bit) and prepends it to the ciphtertext
 * @param {Buffer} plaintext
 * @param {Buffer} key
 * @returns {Buffer}
 */
export function encryptBlob (plaintext: Buffer, key: Buffer): Buffer {
  const nonce = Buffer.allocUnsafe(sodium.crypto_stream_NONCEBYTES)
  sodium.randombytes_buf(nonce)

  const ciphertext = Buffer.allocUnsafe(sodium.crypto_stream_NONCEBYTES + plaintext.length)
  nonce.copy(ciphertext)

  sodium.crypto_stream_xor(ciphertext.slice(sodium.crypto_stream_NONCEBYTES), plaintext, nonce, key)
  return ciphertext
}

/**
 * @param {Buffer} ciphertext
 * @param {Buffer} key
 * @returns {Buffer}
 */
export function decryptBlob (ciphertext: Buffer, key: Buffer) {
  const nonce = ciphertext.slice(0, sodium.crypto_stream_NONCEBYTES)
  const plaintext = Buffer.allocUnsafe(ciphertext.length - sodium.crypto_stream_NONCEBYTES)
  sodium.crypto_stream_xor(plaintext, ciphertext.slice(sodium.crypto_stream_NONCEBYTES), nonce, key)
  return plaintext
}

/**
 * ChaCha20 encryption for random access to a block stream, uses the index as nonce.
 * Use ONLY when it is guaranteed that the (key,nonce) combination is only used once (e.g. for a hypercore)!
 * @param {Buffer} plaintext data to encrypt
 * @param {number} index
 * @param {Buffer} key
 * @returns {Buffer}
 */
export function encryptBlockStream (plaintext: Buffer, index: number, key: Buffer): Buffer {
  const ciphertext = Buffer.allocUnsafe(plaintext.length)
  const nonce = Buffer.alloc(sodium.crypto_stream_chacha20_NONCEBYTES)
  nonce.writeBigUInt64LE(BigInt(index))

  sodium.crypto_stream_chacha20_xor(ciphertext, plaintext, nonce, key)
  return ciphertext
}

/**
 * @param {Buffer} ciphertext
 * @param {number} index
 * @param {Buffer} key of length sodium.crypto_stream_chacha20_KEYBYTES
 * @returns {Buffer}
 */
export function decryptBlockStream (ciphertext: Buffer, index: number, key: Buffer) {
  const plaintext = Buffer.allocUnsafe(ciphertext.length)
  const nonce = Buffer.alloc(sodium.crypto_stream_chacha20_NONCEBYTES)
  nonce.writeBigUInt64LE(BigInt(index))

  sodium.crypto_stream_chacha20_xor(plaintext, ciphertext, nonce, key)
  return plaintext
}

/**
 * @returns {import('sodium-native').SecureBuffer}
 */
export function generateEncryptionKey (): Buffer {
  const key = sodium.sodium_malloc(sodium.crypto_stream_KEYBYTES)
  sodium.randombytes_buf(key)
  return key
}

/**
 * Copies the buffer to a memory-protected buffer and zeroes out the original one
 * @param {Buffer} buf
 * @returns {import('sodium-native').SecureBuffer}
 */
export function extractEncryptionKey (buf: Buffer) {
  if (!Buffer.isBuffer(buf)) {
    throw new Error('key is not an instance of Buffer')
  }
  if (buf.length !== sodium.crypto_stream_KEYBYTES) {
    throw new Error('key has invalid length')
  }
  const key = sodium.sodium_malloc(sodium.crypto_stream_KEYBYTES)
  buf.copy(key)
  buf.fill(0)
  return key
}

/**
 * @param {Buffer|string} buf
 */
export function hash (buf: Buffer): Buffer {
  if (!Buffer.isBuffer(buf)) {
    buf = Buffer.from(buf)
  }
  const out = Buffer.allocUnsafe(sodium.crypto_generichash_BYTES)
  sodium.crypto_generichash(out, buf)
  return out
}

export function crypto_box_seal(pubkey: Buffer, message: Buffer): Buffer {
  if(!Buffer.isBuffer(pubkey) || pubkey.length !== sodium.crypto_box_PUBLICKEYBYTES) {
    throw new Error('invalid public key: ' + pubkey?.toString())
  }

  const ciphertext = Buffer.allocUnsafe(sodium.crypto_box_SEALBYTES + message.length)
  sodium.crypto_box_seal(ciphertext, message, pubkey)
  return ciphertext
}

export function crypto_box_seal_open(pubkey: Buffer, secretkey: Buffer, ciphertext: Buffer): Buffer | null {
  if(!Buffer.isBuffer(pubkey) || pubkey.length !== sodium.crypto_box_PUBLICKEYBYTES) {
    throw new Error('invalid public key: ' + pubkey?.toString())
  }

  if(!Buffer.isBuffer(secretkey) || secretkey.length !== sodium.crypto_box_SECRETKEYBYTES) {
    throw new Error('invalid secret key!')
  }

  const message = Buffer.allocUnsafe(ciphertext.length - sodium.crypto_box_SEALBYTES)
  if(!sodium.crypto_box_seal_open(message, ciphertext, pubkey, secretkey)) {
    return null
  } else {
    return message
  }
}

export function generateUserKeyPair() {
  // the private key has to be more secure than other secret keys (secure buffers are a limited resource)
  const pubkey = sodium.sodium_malloc(sodium.crypto_box_PUBLICKEYBYTES)
  const secretkey = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES)
  sodium.crypto_box_keypair(pubkey, secretkey)
  return {pubkey, secretkey}
}

export function validateUserPublicKey(key: Buffer) {
  return Buffer.isBuffer(key) && key.length === sodium.crypto_box_PUBLICKEYBYTES
}

export function validateUserSecretKey(key: Buffer) {
  return Buffer.isBuffer(key) && key.length === sodium.crypto_box_SECRETKEYBYTES
}