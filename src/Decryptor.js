const nacl = require('libsodium-wrappers')

module.exports = async (key) => {
    await nacl.ready;
    if(key === undefined) throw 'no key';
    
    return Object.freeze({
        decrypt : (ciphertext, nonce) => nacl.crypto_secretbox_open_easy(ciphertext, nonce, key)
    });
}