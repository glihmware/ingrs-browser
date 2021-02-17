/*
  This file is part of ingrs project.

  MIT License

  Copyright (c) 2021 glihmware

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.

  Credit: Adapted from https://github.com/antelle/argon2-browser.git.
*/

import { B64 } from './b64';


/*
 * argon2.js glue code, in accordance with the targeted
 * wasm file.
 */
import Module from '../js/argon2.js';


/*
 * Argon2 types (Argon2id is recommended).
 */
export enum Argon2Type
{
  Argon2d = 0,
  Argon2i = 1,
  Argon2id = 2,

}

/*
 * Argon2 parameters.
 *
 * FIXME: in this version, associated data (ad)
 *        and secret are ignored.
 */
export interface Argon2Params
{
  // Memory costs.
  mem: number;
  // Number of core.
  parallel: number;

  // Iteration count.
  iter: number;
  // Hash length in byte.
  hashLen: number;

  // Base64 of the salt.
  salt: string;

  // Argon2 type.
  type: Argon2Type;

}


/*
 * Argon2 PHF.
 */
export class Argon2
{
  //
  module: any;

  //
  private __ready: boolean;

  /*
   *
   */
  constructor()
  {
    this.__ready = false;
  }

  /*
   * Instanciates argon2 from distant wasm.
   */
  public async instanciate(wasm_url: string, ecdsa_wasm_pub: string)
  : Promise<boolean>
  {
    const wasmBuf = await this.__fetchWasm(wasm_url);

    if (wasmBuf == null)
    {
      return false;
    }

    const binary = new Uint8Array(wasmBuf)

    let isBinarySafe = this.__checkWasm(binary, ecdsa_wasm_pub);
    if (!isBinarySafe)
    {
      console.error("error verifying wasm signature");
      return false;
    }

    const moduleArgs = {
      wasmBinary: binary,
      onRuntimeInitialized: () => {
        //console.log("INIT");
        this.__ready = true;
        //console.log("READY", this.__ready);
      },
    }

    this.module = await Module(moduleArgs);
    return true;
  }

  /*
   * Checks the argon2 wasm ECDSA signature.
   */
  private __checkWasm(wasm: Uint8Array, signature: string)
  : boolean
  {
    // const ecdsaPubB64 = environment.argon2_ecdsa_pub;
    // const ecdsaKey = this.__b64.decode(ecdsaPubB64);

    // // import the key as cryptokey
    // const result = crypto.subtle.importKey(
    //   'pcks8',
    //   ecdsaKey,
    //   {
    //     name: 'ECDSA',
    //     namedCurve: 'P-521'
    //   },
    //   false,
    //   ['verify']
    // );

    // verify.

    return true;
  }


  /*
   * Computes argon2 hash from passwd with the given parameters.
   */
  public async computeHash(passwd: string, params: Argon2Params) {

    if (!this.__ready)
    {
      return "not ready";
    }

    return await this.__computeHash(passwd, params);
  }


  /*
   *
   */
  private async __fetchWasm(url: string)
  {
    let rsp = await fetch(url);

    if (rsp.ok)
    {
      return await rsp.arrayBuffer();
    }

    return null;
  }


  /*
   * Computes hash from passwd.
   */
  private async __computeHash(passwd: string, params: Argon2Params) {

    let m = await this.module;

    if (!m._argon2_hash_ext) {
      console.error('Error 1');
      return;
    }

    let mem = params.mem;
    let parallelism = params.parallel;

    let iter = params.iter;
    let hashlen = 32;

    let passEncoded = this.__encodeUtf8(passwd);
    let pwd = m.allocate(passEncoded, 'i8', m.ALLOC_NORMAL);
    let pwdlen = passEncoded.length;

    let argon2_type = params.type;

    let saltEncoded = B64.decode(params.salt);
    let salt = m.allocate(saltEncoded, 'i8', m.ALLOC_NORMAL);
    let saltlen = saltEncoded.length;

    let hash = m.allocate(
      new Array(hashlen),
      'i8',
      m.ALLOC_NORMAL
    );

    let encodedlen = m._argon2_encodedlen(
      iter,
      mem,
      parallelism,
      saltlen,
      hashlen,
      argon2_type
    );

    let encoded = m.allocate(
      new Array(encodedlen + 1),
      'i8',
      m.ALLOC_NORMAL
    );

    let secret = 0;
    let secretlen = 0;
    let ad = 0;
    let adlen = 0;
    let version = 0x13;
    let err;
    let res;

    try {
      res = m._argon2_hash_ext(
        iter,
        mem,
        parallelism,
        pwd,
        pwdlen,
        salt,
        saltlen,
        hash,
        hashlen,
        encoded,
        encodedlen,
        argon2_type,
        secret,
        secretlen,
        ad,
        adlen,
        version
      );
    } catch (e) {
      err = e;
    }

    if (res === 0 && !err) {
      let hashArr = [];
      for (let i = hash; i < hash + hashlen; i++) {
        hashArr.push(m.HEAP8[i]);
      }

      return m.UTF8ToString(encoded);

    }
    else
    {
      try {
        if (!err) {
          err = m.UTF8ToString(m._argon2_error_message(res));
        }
      } catch (e) {}
      console.error('Error: ' + res + (err ? ': ' + err : ''));
    }
    try {
      m._free(pwd);
      m._free(salt);
      m._free(hash);
      m._free(encoded);
    } catch (e) {}
  }

  /*
   *
   */
  private __encodeUtf8(str: string) {
    return new TextEncoder().encode(str);
  }


}

