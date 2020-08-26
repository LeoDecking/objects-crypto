// import { ObjectsKeyType, PrivateEncryptionKey, PublicEncryptionKey } from "./Keys";
// import crypto from "../crypto";

// export class WrapKey {
//     readonly keyType = ObjectsKeyType.Wrap;
//     readonly alorithm = "AES-KW";
//     readonly keyUsages = ["wrapKey", "unwrapKey"];


//     readonly key?: CryptoKey;

//     constructor(key?: CryptoKey) {
//         this.key = key;
//     }

//     static async derive(privateEncryptionKey: PrivateEncryptionKey, publicEncryptionKey: PublicEncryptionKey): Promise<WrapKey> {
//         let dummy = new this();
//         return new WrapKey(await crypto.subtle.deriveKey({ name: "ECDH", public: publicEncryptionKey.key! }, privateEncryptionKey.key!, { name: dummy.alorithm, length: 256 }, false, dummy.keyUsages));
//     }
// }
