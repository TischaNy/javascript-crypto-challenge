const nacl = require('libsodium-wrappers')
const Decryptor = require('./Decryptor.js');
const Encryptor = require('./Encryptor.js');

let encryptor;
let decryptor;

let result = {}

module.exports = async (otherPeer) => {
    await nacl.ready;
    
    let keys = nacl.crypto_box_keypair();

    if(otherPeer){  
        let server = nacl.crypto_kx_keypair();
        let client = otherPeer.setServer(server.publicKey);
        clientSessionKeys = client.sharedKeys;
        serverSessionKeys = nacl.crypto_kx_server_session_keys(server.publicKey, server.privateKey, client.publicKey);
  
        encryptor = await Encryptor(clientSessionKeys.sharedTx);
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

        setServer : (server) => {
            let client = nacl.crypto_kx_keypair();
            return {
                publicKey : client.publicKey,
                sharedKeys : nacl.crypto_kx_client_session_keys(client.publicKey, client.privateKey, server)
            }
        }
    });
}