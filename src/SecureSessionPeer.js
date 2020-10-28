const nacl = require('libsodium-wrappers')

let keys;
let server = {}
let client = {}
let result = {}

module.exports = async (otherPeer) => {
    await nacl.ready;
    keys = nacl.crypto_box_keypair();

    if(otherPeer){
        server = nacl.crypto_kx_keypair();
    }else{
        client = nacl.crypto_kx_keypair();
    }

    return Object.freeze({
        publicKey : keys.publicKey,
        encrypt : (msg) => {
            let sharedKeys = nacl.crypto_kx_client_session_keys(client.publicKey, client.privateKey, server.publicKey);
            let nonce = nacl.randombytes_buf(nacl.crypto_secretbox_NONCEBYTES);
            return {
                ciphertext: nacl.crypto_secretbox_easy(msg, nonce, sharedKeys.sharedTx),
                nonce : nonce
            }
        },

        decrypt : (ciphertext, nonce) => {
            let sharedKeys = nacl.crypto_kx_server_session_keys(server.publicKey, server.privateKey, client.publicKey);
            return nacl.crypto_secretbox_open_easy(ciphertext, nonce, sharedKeys.sharedRx);
        },

        send : (msg) => {
            let sharedKeys = nacl.crypto_kx_client_session_keys(client.publicKey, client.privateKey, server.publicKey);
            let nonce = nacl.randombytes_buf(nacl.crypto_secretbox_NONCEBYTES)
            result = {
                nonce : nonce,
                ciphertext : nacl.crypto_secretbox_easy(msg, nonce, sharedKeys.sharedTx),
            }
        },

        receive : () => {
            if(result){
                let sharedKeys = nacl.crypto_kx_server_session_keys(server.publicKey, server.privateKey, client.publicKey);
                msg = nacl.crypto_secretbox_open_easy(result.ciphertext, result.nonce, sharedKeys.sharedRx);
            }
            result = {};
            return msg;
        }
    });
}