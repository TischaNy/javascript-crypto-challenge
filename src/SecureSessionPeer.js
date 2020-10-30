const nacl = require('libsodium-wrappers')
const Decryptor = require('./Decryptor.js');
const Encryptor = require('./Encryptor.js');

let result = {}

module.exports = async (client) => {
    await nacl.ready;
    
    let encryptor;
    let decryptor;

    let keys = nacl.crypto_kx_keypair();

    if(client){  
        await client.setClientSession(keys.publicKey);
        let serverSessionKeys = nacl.crypto_kx_server_session_keys(keys.publicKey, keys.privateKey, client.publicKey);
  
        encryptor = await Encryptor(serverSessionKeys.sharedTx);
        decryptor = await Decryptor(serverSessionKeys.sharedRx);

    }
    return Object.freeze({
        publicKey : keys.publicKey,
        encrypt : (msg) => {
            return encryptor.encrypt(msg);
        },

        decrypt : (ciphertext, nonce) => {
            return decryptor.decrypt(ciphertext, nonce);
        },

        send : (msg) => {
            result = encryptor.encrypt(msg);
        },

        receive : () => {
            let msg;
            if(result){
                msg = decryptor.decrypt(result.ciphertext, result.nonce);
                result = {};
            }
            return msg;
        },

        setClientSession : async (serverPublicKey) => {
            let clientSessionKeys =  nacl.crypto_kx_client_session_keys(keys.publicKey, keys.privateKey, serverPublicKey);
            encryptor = await Encryptor(clientSessionKeys.sharedTx);
            decryptor = await Decryptor(clientSessionKeys.sharedRx);
        }
    });
}