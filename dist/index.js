"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DefaultCrypto = exports.Primitives = exports.Cipher = void 0;
const Primitives = __importStar(require("./lib/primitives"));
exports.Primitives = Primitives;
const Key_1 = require("./lib/Key");
Object.defineProperty(exports, "Cipher", { enumerable: true, get: function () { return Key_1.Cipher; } });
const KeyCache_1 = require("./lib/KeyCache");
class DefaultCrypto {
    constructor() {
        this.keys = new KeyCache_1.KeyCache();
    }
    registerKey(key, def) {
        this.keys.set(def.feed, def.index, { key, def });
    }
    unregisterKey(feed, index) {
        this.keys.delete(feed, index);
    }
    registerPublic(feed, index) {
        this.keys.set(feed, index, { public: true });
    }
    unregisterPublic(feed, index) {
        this.keys.delete(feed, index);
    }
    registerUserKeyPair(pubkey, secretkey) {
        this.userKeyPair = { pubkey, secretkey };
    }
    hasKey(feed, index) {
        return !!this.keys.get(feed, index);
    }
    getKey(feed, index) {
        var _a, _b;
        const entry = this.keys.get(feed, index);
        if ((_a = entry) === null || _a === void 0 ? void 0 : _a.key)
            return (_b = entry) === null || _b === void 0 ? void 0 : _b.key;
        else
            return null;
    }
    encrypt(plaintext, keydef, key) {
        if (!key) {
            const res = this.keys.get(keydef.feed, keydef.index);
            if (!res) {
                throw new Error(`Key not found: ${keydef.feed} @ ${keydef.index}`);
            }
            else if (res.public) {
                return plaintext;
            }
            const kd = res;
            key = kd === null || kd === void 0 ? void 0 : kd.key;
            if ((kd === null || kd === void 0 ? void 0 : kd.def.type) !== keydef.type) {
                throw new Error(`Key Cipher does not match the registered one: ${kd === null || kd === void 0 ? void 0 : kd.def.type} - ${keydef.type}`);
            }
        }
        if (!Buffer.isBuffer(key))
            throw new Error(`encryption key "${keydef.feed}@${keydef.index}" not found`);
        switch (keydef.type) {
            case Key_1.Cipher.ChaCha20_Stream:
                if (typeof keydef.nonce !== 'number')
                    throw new Error('ChaCha20_Stream requires an index as nonce');
                return Primitives.encryptBlockStream(plaintext, keydef.nonce, key);
            case Key_1.Cipher.XChaCha20_Blob:
                return Primitives.encryptBlob(plaintext, key);
            default:
                throw new Error('Unknown encryption algorithm ID: ' + keydef.type);
        }
    }
    decrypt(ciphertext, keydef, key) {
        if (!key) {
            const res = this.keys.get(keydef.feed, keydef.index);
            if (!res) {
                throw new Error(`Key not found: ${keydef.feed} @ ${keydef.index}`);
            }
            else if (res.public) {
                return ciphertext;
            }
            const kd = res;
            key = kd.key;
            if (kd.def.type !== keydef.type) {
                throw new Error(`Key Cipher does not match the registered one: ${kd === null || kd === void 0 ? void 0 : kd.def.type} - ${keydef.type}`);
            }
        }
        if (!Buffer.isBuffer(key))
            throw new Error(`decryption key "${keydef.feed}@${keydef.index}" not found`);
        switch (keydef.type) {
            case Key_1.Cipher.ChaCha20_Stream:
                if (typeof keydef.nonce !== 'number')
                    throw new Error('ChaCha20_Stream requires an index as nonce');
                return Primitives.decryptBlockStream(ciphertext, keydef.nonce, key);
            case Key_1.Cipher.XChaCha20_Blob:
                return Primitives.decryptBlob(ciphertext, key);
            default:
                throw new Error('Unknown decryption algorithm ID: ' + keydef.type);
        }
    }
    generateEncryptionKey(algo) {
        switch (algo) {
            case Key_1.Cipher.ChaCha20_Stream:
            case Key_1.Cipher.XChaCha20_Blob:
                return Primitives.generateEncryptionKey();
            default:
                throw new Error('Unknown algorithm ID: ' + algo);
        }
    }
    hash(data) {
        return Primitives.hash(data);
    }
    sealEnvelope(receipient, message) {
        return Primitives.crypto_box_seal(receipient, message);
    }
    tryOpenEnvelope(ciphertext) {
        if (!this.userKeyPair)
            throw new Error('no user key pair registered');
        return Primitives.crypto_box_seal_open(this.userKeyPair.pubkey, this.userKeyPair.secretkey, ciphertext);
    }
}
exports.DefaultCrypto = DefaultCrypto;
//# sourceMappingURL=index.js.map