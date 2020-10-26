const nacl = require('libsodium-wrappers')

module.exports = async (key) => {
    await nacl.ready;
    
    return Object.freeze({
        decrypt : (ciphertext, nonce) => crypto_secretbox_open(ciphertext, nonce)
    });
}
