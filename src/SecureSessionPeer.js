const nacl = require('libsodium-wrappers')

let keys;
let nonce;
let result;
let tx;
let rx;

const server = {
    publicKey : undefined,
    privateKey : undefined
}

const client = {
    publicKey : undefined,
    privateKey : undefined
}
 

module.exports = async (otherPeer) => {
    await nacl.ready;
    keys = nacl.crypto_box_keypair();

    if(otherPeer){
        let server_keys = nacl.crypto_kx_keypair();
        server.publicKey = server_keys.publicKey
        server.privateKey = server_keys.privateKey;
    }else{
        let client_keys = nacl.crypto_kx_keypair();
        client.publicKey = client_keys.publicKey
        client.privateKey = client_keys.privateKey;
    }

    return Object.freeze({
        publicKey : keys.publicKey,
        encrypt : (msg) => {
            nonce = nacl.randombytes_buf(nacl.crypto_secretbox_NONCEBYTES);
            let sharedKeys = nacl.crypto_kx_client_session_keys(keys.publicKey, keys.privateKey, server.publicKey);
       
            return {
                ciphertext: nacl.crypto_secretbox_easy(msg, nonce, sharedKeys.sharedTx),
                nonce : nonce
            }
     
        },

        decrypt : (ciphertext, nonce) => {
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
            
            return msg;
        }

  
    });
}