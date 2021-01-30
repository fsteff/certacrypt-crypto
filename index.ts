import * as Primitives from './lib/primitives'
import { KeyDef, Cipher } from './lib/Key'

export interface ICrypto {
    registerKey(key: Buffer, def: KeyDef)
    unregisterKey(id: string)
    hasKey(id: string): boolean
    getKey(id: string): Buffer | undefined
    encrypt(plaintext: Buffer, keydef: KeyDef, key?: Buffer): Buffer
    decrypt(ciphertext: Buffer, keydef: KeyDef, key?: Buffer): Buffer
    generateEncryptionKey(algo: Cipher): Buffer
    hash(data: Buffer): Buffer
}

export {KeyDef, Cipher, Primitives}

export class DefaultCrypto implements ICrypto{
    private keys = new Map<string, { key: Buffer, def: KeyDef }>()

    registerKey(key: Buffer, def: KeyDef) {
        this.keys.set(def.id, {key, def})
    }

    unregisterKey(id: string) {
        this.keys.delete(id)
    }

    hasKey(id: string) {
        return this.keys.has(id)
    }

    getKey(id: string) {
        return this.keys.get(id)?.key
    }

    encrypt(plaintext: Buffer, keydef: KeyDef, key?: Buffer) {
        if(!key) {
            const kd = this.keys.get(keydef.id)
            key = kd?.key
            if(kd?.def.type !== keydef.type) throw new Error(`Key Cipher does not match the registered one: ${kd?.def.type} - ${keydef.type}`)
        }
        if(!Buffer.isBuffer(key)) throw new Error(`encryption key "${keydef.id}" not found`)
        switch(keydef.type) {
            case Cipher.ChaCha20_Stream:
                if(!keydef.nonce || typeof keydef.nonce !== 'number') throw new Error('ChaCha20_Stream requires an index as nonce')
                return Primitives.encryptBlockStream(plaintext, keydef.nonce, key)

            case Cipher.XChaCha20_Blob:
                return Primitives.encryptBlob(plaintext, key)
            
            default:
                throw new Error('Unknown encryption algorithm ID: ' + keydef.type)
        }
    }

    decrypt(ciphertext: Buffer, keydef: KeyDef, key?: Buffer) {
        if(!key) {
            const kd = this.keys.get(keydef.id)
            key = kd?.key
            if(kd?.def.type !== keydef.type) throw new Error(`Key Cipher does not match the registered one: ${kd?.def.type} - ${keydef.type}`)
        }
        if(!Buffer.isBuffer(key)) throw new Error(`decryption key "${keydef.id}" not found`)
        switch(keydef.type) {
            case Cipher.ChaCha20_Stream:
                if(!keydef.nonce || typeof keydef.nonce !== 'number') throw new Error('ChaCha20_Stream requires an index as nonce')
                return Primitives.decryptBlockStream(ciphertext, keydef.nonce, key)

            case Cipher.XChaCha20_Blob:
                return Primitives.decryptBlob(ciphertext, key)    

            default:
                throw new Error('Unknown decryption algorithm ID: ' + keydef.type)
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