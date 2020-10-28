const nacl = require("libsodium-wrappers");


exports.encrypt = async (msg, nonce, key) => {
    await nacl.ready();
    if(key === undefined) throw 'no key';
    let nonce = nacl.randombytes_buf(nacl.crypto_secretbox_NONCEBYTES);
    return {
        ciphertext: nacl.crypto_secretbox_easy(msg, nonce, key),
        nonce: nonce
    };
};