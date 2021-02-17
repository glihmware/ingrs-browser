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

  Code inspired from CryptoJS.
  https://github.com/sytelus/CryptoJS/blob/master/components/enc-base64.js
  Licence at: https://code.google.com/archive/p/crypto-js/wikis/License.wiki
*/


/*
 * Base 64 encode - decode.
 */
export class B64
{
  // Map of b64 caracter set.
  private static __map: string
    = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';

  /*
   * Encodes the given buffer into a base64 string.
   */
  public static encode(buf: Uint8Array)
  : string
  {
    // FIXME: to be replaced.
    return btoa(String.fromCharCode.apply(null, Array.from(buf)));
  }

  /*
   * Encodes the given string into a base64 string.
   */
  public static encodeStr(str: string)
  : string
  {
    let buf = new TextEncoder().encode(str);
    return B64.encode(buf);
  }

  /*
   * Decodes the given base64 string into a buffer.
   */
  public static decode(b64: string)
  : Uint8Array
  {
    let base64StrLength = b64.length;

    // Ignore padding.
    let paddingChar = B64.__map.charAt(64);
    if (paddingChar)
    {
      let paddingIndex = b64.indexOf(paddingChar);
      if (paddingIndex != -1)
      {
        base64StrLength = paddingIndex;
      }
    }

    // Convert.
    let buf: any[] = [];
    let nBytes = 0;

    for (var i = 0; i < base64StrLength; i++)
    {
      if (i % 4)
      {
        let bits1 = B64.__map.indexOf(b64.charAt(i - 1)) << ((i % 4) * 2);
        let bits2 = B64.__map.indexOf(b64.charAt(i)) >>> (6 - (i % 4) * 2);
        buf[nBytes >>> 2] |= (bits1 | bits2) << (24 - (nBytes % 4) * 8);
        nBytes++;
      }
    }

    let bytes = B64.__warray2bytes(buf, nBytes);

    return new Uint8Array(bytes);
  }


  /*
   * Converts a 32-bit word array to a bytes array.
   *
   * Credit to:
   * https://gist.github.com/artjomb/7ef1ee574a411ba0dd1933c1ef4690d1
   */
  private static __warray2bytes(warray: number[], length: number)
  {
    let result: any[] = [];
    let bytes: any[] = [];
    let i = 0;

    while (length > 0)
    {
      bytes = B64.__w2bytes(warray[i], Math.min(4, length));
      length -= bytes.length;
      result = result.concat(bytes);
      i++;
    }

    return result;
  }


  /*
   * Converts a 32-bit word to a bytes array.
   *
   * Credit to:
   * https://gist.github.com/artjomb/7ef1ee574a411ba0dd1933c1ef4690d1
   */
  private static __w2bytes(word: number, length: number)
  {
    let ba = [],
    i,
    xFF = 0xFF;
    if (length > 0)
      ba.push(word >>> 24);
    if (length > 1)
      ba.push((word >>> 16) & xFF);
    if (length > 2)
      ba.push((word >>> 8) & xFF);
    if (length > 3)
      ba.push(word & xFF);

    return ba;

  }

}


