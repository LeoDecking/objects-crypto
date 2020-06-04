import { getCurveByName } from "ecurve";
import { ObjectsKeyType, PublicKey, VerifyKey, PublicEncryptionKey } from "./Keys";
import { Key } from "./Key";
import * as utf8 from "@stablelib/utf8";
import * as base64 from "@stablelib/base64";

import bigi from "bigi";


export abstract class PrivateKey<K extends ObjectsKeyType> extends Key<K>  {

    abstract publicKeyUsages: string[];

    constructor(keyPair?: CryptoKeyPair) {
        super(keyPair?.privateKey);
    }

    // TODO publicKey is empty
    static async import<K extends PrivateKey<ObjectsKeyType>>(this: new (keyPair?: CryptoKeyPair) => K, privateKey: Uint8Array): Promise<K> {
        let jwk: JsonWebKey = {};
        jwk.crv = "P-256";
        jwk.ext = true;
        jwk.kty = "EC";
        let publicKey = getCurveByName("secp256r1").G.multiply(bigi.fromBuffer(privateKey)).getEncoded(false);
        jwk.x = base64.encodeURLSafe(publicKey.slice(1, 33)).substr(0, 43);
        jwk.y = base64.encodeURLSafe(publicKey.slice(33)).substr(0, 43);
        let privateJWK = { ...jwk, d: base64.encodeURLSafe(privateKey).substr(0, 43) };
        let dummy = new this();
        return new this(await Promise.all([
            crypto.subtle.importKey("jwk", privateJWK, { name: dummy.alorithm, namedCurve: "P-256" }, false, dummy.keyUsages),
            crypto.subtle.importKey("jwk", jwk, { name: dummy.alorithm, namedCurve: "P-256" }, true, dummy.publicKeyUsages)
        ]).then(keys => ({ privateKey: keys[0], publicKey: keys[1] })));
    }

    static async generate<K extends PrivateKey<ObjectsKeyType>>(this: new (keyPair?: CryptoKeyPair) => K, password?: string, salt?: string): Promise<K> {
        let dummy = new this();
        let result = password
            ? await Key.generateBits(password, (salt ?? "") + dummy.keyType)
            : crypto.getRandomValues(new Uint8Array(32));
        return await PrivateKey.import.call(this, result);
    }

    // exportable must be set to true
    // async export(): Promise<string> {
    //     let jwk = await crypto.subtle.exportKey("jwk", this.key!);
    //     return jwk.x!;
    // }
}

export class SignKey extends PrivateKey<ObjectsKeyType.Sign> {
    readonly keyType = ObjectsKeyType.Sign;
    readonly alorithm = "ECDSA";
    readonly keyUsages = ["sign"];
    readonly publicKeyUsages = ["verify"];

    readonly verifyKey: VerifyKey;

    constructor(keyPair?: CryptoKeyPair) {
        super(keyPair);
        this.verifyKey = new VerifyKey(keyPair?.publicKey);
    }
}

export class PrivateEncryptionKey extends PrivateKey<ObjectsKeyType.PrivateEncryption> {
    readonly keyType = ObjectsKeyType.PrivateEncryption;
    readonly alorithm = "ECDH";
    readonly keyUsages = ["deriveKey"];
    readonly publicKeyUsages = [];

    readonly publicKey: PublicEncryptionKey;

    constructor(keyPair?: CryptoKeyPair) {
        super(keyPair);
        this.publicKey = new PublicEncryptionKey(keyPair?.publicKey);
    }
}