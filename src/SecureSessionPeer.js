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
        let clientSessionKeys = client.getClientSession(keys.publicKey);
        let serverSessionKeys = nacl.crypto_kx_server_session_keys(keys.publicKey, keys.privateKey, client.publicKey);
  
        encryptor = await Encryptor(serverSessionKeys.sharedTx);
        decryptor = await Decryptor(serverSessionKeys.sharedRx);
        client.setEncryptor(await Encryptor(clientSessionKeys.sharedTx));
        client.setDecryptor(await Decryptor(clientSessionKeys.sharedRx));
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

        getClientSession : (serverPublicKey) => {
            return nacl.crypto_kx_client_session_keys(keys.publicKey, keys.privateKey, serverPublicKey);
        },

        setEncryptor : (_encryptor) => {
            encryptor = _encryptor;
        },

        setDecryptor : (_decryptor) => {
            decryptor = _decryptor;
        }
    });
}