import * as Primitives from './lib/primitives'
import { KeyDef, Cipher } from './lib/Key'
import { KeyCache, KeyEntry, PublicEntry } from './lib/KeyCache'

export interface ICrypto {
    registerKey(key: Buffer, def: KeyDef)
    unregisterKey(feed: string, index?: string|number)
    registerPublic(feed: string, index: string|number)
    unregisterPublic(feed: string, index?: string|number)
    hasKey(feed: string, index: string|number): boolean
    getKey(feed: string, index: string|number): Buffer | null
    encrypt(plaintext: Buffer, keydef: KeyDef, key?: Buffer): Buffer
    decrypt(ciphertext: Buffer, keydef: KeyDef, key?: Buffer): Buffer
    generateEncryptionKey(algo: Cipher): Buffer
    hash(data: Buffer): Buffer
}

export {KeyDef, Cipher, Primitives}

export class DefaultCrypto implements ICrypto{

    private userKeyPair?: {pubkey: Buffer, secretkey: Buffer}

    private keys = new KeyCache()

    registerKey(key: Buffer, def: KeyDef) {
        this.keys.set(def.feed, def.index, {key, def})
    }

    unregisterKey(feed: string, index?: number | string) {
        this.keys.delete(feed, index)
    }

    registerPublic(feed: string, index: string|number) {
        this.keys.set(feed, index, {public: true})
    }
    unregisterPublic(feed: string, index?: string|number){
        this.keys.delete(feed, index)
    }

    registerUserKeyPair(pubkey: Buffer, secretkey: Buffer) {
        this.userKeyPair = {pubkey, secretkey}
    }

    hasKey(feed: string, index: string | number) {
        return !!this.keys.get(feed, index)
    }

    getKey(feed: string, index: string | number) {
        const entry = this.keys.get(feed, index)
        if((<KeyEntry>entry)?.key) return (<KeyEntry>entry)?.key
        else return null
    }

    encrypt(plaintext: Buffer, keydef: KeyDef, key?: Buffer) {
        if(!key) {
            const res = this.keys.get(keydef.feed, keydef.index)
            if(!res) {
                throw new Error(`Key not found: ${keydef.feed} @ ${keydef.index}`)
            } else if((<PublicEntry>res).public) {
                return plaintext 
            } 
            const kd = <KeyEntry>res
            key = kd?.key
            if(kd?.def.type !== keydef.type) {
                throw new Error(`Key Cipher does not match the registered one: ${kd?.def.type} - ${keydef.type}`)
            }
        }
        if(!Buffer.isBuffer(key)) throw new Error(`encryption key "${keydef.feed}@${keydef.index}" not found`)
        switch(keydef.type) {
            case Cipher.ChaCha20_Stream:
                if(typeof keydef.nonce !== 'number') throw new Error('ChaCha20_Stream requires an index as nonce')
                return Primitives.encryptBlockStream(plaintext, keydef.nonce, key)

            case Cipher.XChaCha20_Blob:
                return Primitives.encryptBlob(plaintext, key)
            
            default:
                throw new Error('Unknown encryption algorithm ID: ' + keydef.type)
        }
    }

    decrypt(ciphertext: Buffer, keydef: KeyDef, key?: Buffer) {
        if(!key) {
            const res = this.keys.get(keydef.feed, keydef.index)
            if(!res) {
                throw new Error(`Key not found: ${keydef.feed} @ ${keydef.index}`)
            } else if((<PublicEntry>res).public) {
                return ciphertext 
            } 
            const kd = <KeyEntry>res
            key = kd.key
            if(kd.def.type !== keydef.type) {
                throw new Error(`Key Cipher does not match the registered one: ${kd?.def.type} - ${keydef.type}`)
            }
        }
        if(!Buffer.isBuffer(key)) throw new Error(`decryption key "${keydef.feed}@${keydef.index}" not found`)
        switch(keydef.type) {
            case Cipher.ChaCha20_Stream:
                if(typeof keydef.nonce !== 'number') throw new Error('ChaCha20_Stream requires an index as nonce')
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

    sealEnvelope(receipient: Buffer, message: Buffer) : Buffer {
        return Primitives.crypto_box_seal(receipient, message)
    }

    tryOpenEnvelope(ciphertext: Buffer) : Buffer | null {
        if(!this.userKeyPair) throw new Error('no user key pair registered')
        return Primitives.crypto_box_seal_open(this.userKeyPair.pubkey, this.userKeyPair.secretkey, ciphertext)
    }
}