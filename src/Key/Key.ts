import { ObjectsKeyType } from "./Keys";
// import * as argon2 from "../argon2";
import argon2 from "../argon2";
import * as utf8 from "@stablelib/utf8";

export abstract class Key<K extends ObjectsKeyType> {
    keyType?: K;
    abstract alorithm: string;
    abstract keyUsages: string[];

    readonly key?: CryptoKey;

    constructor(key?: CryptoKey) {
        this.key = key;
    }

    static async generateBits(password: string, salt: string, m: number = 128): Promise<Uint8Array> {
        if (!password) {
            let a = [...utf8.encode(salt).slice(32)];
            while (a.length != 32) a.push(0);
            return new Uint8Array(a);
        }
        let result = await argon2.hash({ pass: utf8.encode(password), salt: utf8.encode("saltysalt" + salt), hashLen: 32, mem: 1024 * m, time: 1, parallelism: 1, type: argon2.ArgonType.Argon2id });
        return result.hash;
    }
}