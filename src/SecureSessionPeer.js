const nacl = require('libsodium-wrappers')
const Decryptor = require('./Decryptor.js');
const Encryptor = require('./Encryptor.js');

let encryptor;
let decryptor;
let server = {}
let client = {}
let result = {}

module.exports = async (otherPeer) => {
    await nacl.ready;
 
    let serverSessionKeys;
    let clientSessionKeys;
    let keys = nacl.crypto_box_keypair();

    if(otherPeer){
        server = nacl.crypto_kx_keypair();
        client = nacl.crypto_kx_keypair();
        clientSessionKeys = nacl.crypto_kx_client_session_keys(client.publicKey, client.privateKey, server.publicKey);
        serverSessionKeys = nacl.crypto_kx_server_session_keys(server.publicKey, server.privateKey, client.publicKey);
        encryptor = await Encryptor(clientSessionKeys.sharedTx);
        decryptor = await Decryptor(serverSessionKeys.sharedRx);
    }

    if(encryptor === undefined && decryptor == undefined){
        encryptor = await Encryptor(keys.publicKey);
        decryptor = await Decryptor(keys.privateKey);
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
        }
    });
}