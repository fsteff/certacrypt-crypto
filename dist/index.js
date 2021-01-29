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
exports.Crypto = void 0;
const Primitives = __importStar(require("./lib/primitives"));
const Key_1 = require("./lib/Key");
class Crypto {
    constructor() {
        this.keys = new Map();
    }
    registerKey(key, def) {
        this.keys.set(def.id, { key, def });
    }
    unregisterKey(id) {
        this.keys.delete(id);
    }
    encrypt(plaintext, key, def) {
        switch (def.type) {
            case Key_1.Cipher.ChaCha20_Stream:
                if (!def.nonce || typeof def.nonce !== 'number')
                    throw new Error('ChaCha20_Stream requires an index as nonce');
                return Primitives.encryptBlockStream(plaintext, def.nonce, key);
            case Key_1.Cipher.XChaCha20_Blob:
                return Primitives.encryptBlob(plaintext, key);
            default:
                throw new Error('Unknown encryption algorithm ID: ' + def.type);
        }
    }
    decrypt(ciphertext, key, def) {
        switch (def.type) {
            case Key_1.Cipher.ChaCha20_Stream:
                if (!def.nonce || typeof def.nonce !== 'number')
                    throw new Error('ChaCha20_Stream requires an index as nonce');
                return Primitives.decryptBlockStream(ciphertext, def.nonce, key);
            case Key_1.Cipher.XChaCha20_Blob:
                return Primitives.decryptBlob(ciphertext, key);
            default:
                throw new Error('Unknown decryption algorithm ID: ' + def.type);
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
}
exports.Crypto = Crypto;
//# sourceMappingURL=index.js.map