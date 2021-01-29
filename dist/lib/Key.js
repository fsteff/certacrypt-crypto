"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Cipher = void 0;
var Cipher;
(function (Cipher) {
    Cipher[Cipher["XChaCha20_Blob"] = 1] = "XChaCha20_Blob";
    Cipher[Cipher["ChaCha20_Stream"] = 2] = "ChaCha20_Stream"; // ChaCha20 encryption for random access to a block stream, uses the index as nonce - use ONLY when it is guaranteed that the (key,nonce) combination is only used once (e.g. for a hypercore)!
})(Cipher = exports.Cipher || (exports.Cipher = {}));
//# sourceMappingURL=Key.js.map