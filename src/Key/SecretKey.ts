import { ObjectsKeyType } from "./Keys";
import * as base64 from "@stablelib/base64";
import { Key } from "./Key";

// SecretKeys können exportiert werden, deswegen wird jedes Mal ein neuer generiert
// Passwort-basierte SecretKeys natürlich nicht
export class SecretKey extends Key<ObjectsKeyType.Secret> {
    readonly keyType = ObjectsKeyType.Secret;
    readonly alorithm = "AES-GCM";
    readonly keyUsages = ["encrypt", "decrypt"];


    static async import(secretKey: Uint8Array, exportable = false): Promise<SecretKey> {
        let dummy = new SecretKey();
        return new SecretKey(await crypto.subtle.importKey("raw", secretKey, dummy.alorithm, exportable, dummy.keyUsages));
    }

    static async generate(password?: string, salt?: string): Promise<SecretKey> {
        let dummy = new this();
        let result = password
            ? await Key.generateBits(password, salt ?? "", dummy.keyType)
            : crypto.getRandomValues(new Uint8Array(32));
        return await SecretKey.import(result, !password);
    }

    async export(): Promise<string> {
        return base64.encode(new Uint8Array(await crypto.subtle.exportKey("raw", this.key!)));
    }
}
