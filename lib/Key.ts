export enum Cipher {
    XChaCha20_Blob = 1, // XChaCha20 encryption, automatically generates a random nonce (192 Bit) and prepends it to the ciphtertext
    ChaCha20_Stream = 2 // ChaCha20 encryption for random access to a block stream, uses the index as nonce - use ONLY when it is guaranteed that the (key,nonce) combination is only used once (e.g. for a hypercore)!
}

export interface KeyDef {
    feed: string,
    index: string | number
    type: Cipher
    nonce?: Buffer | number
}