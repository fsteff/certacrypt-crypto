import * as Primitives from './lib/primitives'
import { KeyDef, Cipher } from './lib/Key'

export class Crypto {
    private keys = new Map<string, { key: Buffer, def: KeyDef }>()

    registerKey(key: Buffer, def: KeyDef) {
        this.keys.set(def.id, {key, def})
    }

    unregisterKey(id: string) {
        this.keys.delete(id)
    }

    encrypt(plaintext: Buffer, key: Buffer, def: KeyDef) {
        switch(def.type) {
            case Cipher.ChaCha20_Stream:
                if(!def.nonce || typeof def.nonce !== 'number') throw new Error('ChaCha20_Stream requires an index as nonce')
                return Primitives.encryptBlockStream(plaintext, def.nonce, key)

            case Cipher.XChaCha20_Blob:
                return Primitives.encryptBlob(plaintext, key)
            
            default:
                throw new Error('Unknown encryption algorithm ID: ' + def.type)
        }
    }

    decrypt(ciphertext: Buffer, key: Buffer, def: KeyDef) {
        switch(def.type) {
            case Cipher.ChaCha20_Stream:
                if(!def.nonce || typeof def.nonce !== 'number') throw new Error('ChaCha20_Stream requires an index as nonce')
                return Primitives.decryptBlockStream(ciphertext, def.nonce, key)

            case Cipher.XChaCha20_Blob:
                return Primitives.decryptBlob(ciphertext, key)    

            default:
                throw new Error('Unknown decryption algorithm ID: ' + def.type)
        }
    }

    generateEncryptionKey(algo: Cipher) {
        switch(algo) {
            case Cipher.ChaCha20_Stream:
            case Cipher.XChaCha20_Blob:
                return Primitives.generateEncryptionKey()
            default:
                throw new Error('Unknown algorithm ID: ' + algo)
        }
    }

    hash(data: Buffer) {
        return Primitives.hash(data)
    }
}