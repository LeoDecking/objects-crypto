import { ObjectsKeyType } from "./Keys";
import * as utf8 from "@stablelib/utf8";

export abstract class Key<K extends ObjectsKeyType> {
    keyType?: K;
    abstract alorithm: string;
    abstract keyUsages: string[];

    readonly key?: CryptoKey;

    constructor(key?: CryptoKey) {
        this.key = key;
    }

   static async generateBits(password: string, salt: string): Promise<Uint8Array> {
        let result = await (window as any).argon2.hash({ pass: utf8.encode(password), salt: utf8.encode("saltysalt"+salt), hashLen: 32, mem: 131072, time: 1, parallelism: 1, type: (window as any).argon2.ArgonType.Argon2id });
        return result.hash;
    }
}