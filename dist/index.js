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
exports.DefaultCrypto = void 0;
const Primitives = __importStar(require("./lib/primitives"));
const Key_1 = require("./lib/Key");
class DefaultCrypto {
    constructor() {
        this.keys = new Map();
    }
    registerKey(key, def) {
        this.keys.set(def.id, { key, def });
    }
    unregisterKey(id) {
        this.keys.delete(id);
    }
    hasKey(id) {
        return this.keys.has(id);
    }
    getKey(id) {
        var _a;
        return (_a = this.keys.get(id)) === null || _a === void 0 ? void 0 : _a.key;
    }
    encrypt(plaintext, keydef, key) {
        if (!key) {
            const kd = this.keys.get(keydef.id);
            key = kd === null || kd === void 0 ? void 0 : kd.key;
            if ((kd === null || kd === void 0 ? void 0 : kd.def.type) !== keydef.type)
                throw new Error(`Key Cipher does not match the registered one: ${kd === null || kd === void 0 ? void 0 : kd.def.type} - ${keydef.type}`);
        }
        if (!Buffer.isBuffer(key))
            throw new Error(`encryption key "${keydef.id}" not found`);
        switch (keydef.type) {
            case Key_1.Cipher.ChaCha20_Stream:
                if (!keydef.nonce || typeof keydef.nonce !== 'number')
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
            const kd = this.keys.get(keydef.id);
            key = kd === null || kd === void 0 ? void 0 : kd.key;
            if ((kd === null || kd === void 0 ? void 0 : kd.def.type) !== keydef.type)
                throw new Error(`Key Cipher does not match the registered one: ${kd === null || kd === void 0 ? void 0 : kd.def.type} - ${keydef.type}`);
        }
        if (!Buffer.isBuffer(key))
            throw new Error(`decryption key "${keydef.id}" not found`);
        switch (keydef.type) {
            case Key_1.Cipher.ChaCha20_Stream:
                if (!keydef.nonce || typeof keydef.nonce !== 'number')
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
}
exports.DefaultCrypto = DefaultCrypto;
//# sourceMappingURL=index.js.map