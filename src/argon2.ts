export default (window as any).argon2;

// import * as argon2 from "argon2";
// export async function hash(options: Argon2BrowserHashOptions): Promise<{ hash: Uint8Array }> {
//     return {
//         hash: new Uint8Array(await argon2.hash(Buffer.from(options.pass as Uint8Array), {
//             salt: Buffer.from(options.salt),
//             timeCost: options.time,
//             memoryCost: options.mem,
//             hashLength: options.hashLen,
//             parallelism: options.parallelism,
//             type: options.type,
//             raw: true
//         }))
//     };
// }

// interface Argon2BrowserHashOptions {
//     pass: string | Uint8Array;
//     salt: string | Uint8Array;
//     time?: number;
//     mem?: number;
//     hashLen?: number;
//     parallelism?: number;
//     type?: ArgonType;
//     distPath?: string;
// }

// export enum ArgonType {
//     Argon2d = 0,
//     Argon2i = 1,
//     Argon2id = 2,
// }