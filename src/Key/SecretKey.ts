import { ObjectsKeyType, PrivateEncryptionKey, PublicEncryptionKey } from "./Keys";
import * as base64 from "@stablelib/base64";
import { Key } from "./Key";
import crypto from "../crypto";


// SecretKeys können exportiert werden, deswegen wird jedes Mal ein neuer generiert
// Passwort-basierte SecretKeys natürlich nicht
export class SecretKey extends Key<ObjectsKeyType.Secret> {
    readonly keyType = ObjectsKeyType.Secret;
    readonly alorithm = "AES-GCM";
    readonly keyUsages: KeyUsage[] = ["encrypt", "decrypt"];

    readonly export?: PromiseLike<string>;

    constructor(key?: CryptoKey, exportable: boolean = false, string?: string) {
        super(key);

        if (key && exportable) this.export = string ? Promise.resolve(string) : crypto.subtle.exportKey("raw", key).then(raw => base64.encode(new Uint8Array(raw)));
    }

    static async import(secretKey: Uint8Array | number[] | string, exportable = false): Promise<SecretKey> {
        let dummy = new SecretKey();

        if (Array.isArray(secretKey)) secretKey = new Uint8Array(secretKey);

        let bytes = (typeof secretKey) == "string" ? base64.decode(secretKey as string) : secretKey as Uint8Array;
        let string = (typeof secretKey) == "string" ? secretKey as string : base64.encode(secretKey as Uint8Array);

        return new SecretKey(await crypto.subtle.importKey("raw", bytes, dummy.alorithm, false, dummy.keyUsages), exportable, string);
    }

    static async generate(password?: string, salt?: string, m: number=128): Promise<SecretKey> {
        let dummy = new this();
        let result = password != null
            ? await Key.generateBits(password, (salt ?? "") + dummy.keyType, m)
            : crypto.getRandomValues(new Uint8Array(32));
        return await SecretKey.import(result, !password);
    }

    static async derive(privateEncryptionKey: PrivateEncryptionKey, publicEncryptionKey: PublicEncryptionKey): Promise<SecretKey> {
        let dummy = new this();
        return new SecretKey(await crypto.subtle.deriveKey({ name: "ECDH", public: publicEncryptionKey.key! }, privateEncryptionKey.key!, { name: dummy.alorithm, length: 256 }, false, dummy.keyUsages));
    }
}
