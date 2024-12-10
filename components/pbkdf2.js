// From https://www.npmjs.com/package/scrypt-js
// License: MIT

"use strict";
// Utility for int32_to_be
function INT32_BE(value) {
    var array = new Uint8Array(4);
    array[0] = (value >> 24) & 0xFF;
    array[1] = (value >> 16) & 0xFF;
    array[2] = (value >> 8) & 0xFF;
    array[3] = value & 0xFF;
    return array;
}

// Utility to trim array to bits
function TRIM_ARRAY(array, dkLen) {
    const bytesRequired = Math.ceil(dkLen / 8);
    const trimmedArray = array.slice(0, bytesRequired);
    const remainingBits = dkLen % 8;

    if (remainingBits > 0 && trimmedArray.length > 0) {
        const mask = (1 << remainingBits) - 1;
        trimmedArray[trimmedArray.length - 1] &= mask;
    }
    return trimmedArray;
}

var MAX_VALUE = 0x7fffffff;
// The SHA256 and PBKDF2 implementation are from scrypt-async-js:
// See: https://github.com/dchest/scrypt-async-js
function SHA256(m) {
    var K = new Uint32Array([
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]);
    var h0 = 0x6a09e667,
        h1 = 0xbb67ae85,
        h2 = 0x3c6ef372,
        h3 = 0xa54ff53a;
    var h4 = 0x510e527f,
        h5 = 0x9b05688c,
        h6 = 0x1f83d9ab,
        h7 = 0x5be0cd19;
    var w = new Uint32Array(64);
    function blocks(p) {
        var off = 0,
            len = p.length;
        while (len >= 64) {
            var a = h0,
                b = h1,
                c = h2,
                d = h3,
                e = h4,
                f = h5,
                g = h6,
                h = h7,
                u = void 0,
                i_1 = void 0,
                j = void 0,
                t1 = void 0,
                t2 = void 0;
            for (i_1 = 0; i_1 < 16; i_1++) {
                j = off + i_1 * 4;
                w[i_1] =
                    ((p[j] & 0xff) << 24) |
                    ((p[j + 1] & 0xff) << 16) |
                    ((p[j + 2] & 0xff) << 8) |
                    (p[j + 3] & 0xff);
            }
            for (i_1 = 16; i_1 < 64; i_1++) {
                u = w[i_1 - 2];
                t1 =
                    ((u >>> 17) | (u << (32 - 17))) ^
                    ((u >>> 19) | (u << (32 - 19))) ^
                    (u >>> 10);
                u = w[i_1 - 15];
                t2 =
                    ((u >>> 7) | (u << (32 - 7))) ^
                    ((u >>> 18) | (u << (32 - 18))) ^
                    (u >>> 3);
                w[i_1] =
                    (((t1 + w[i_1 - 7]) | 0) + ((t2 + w[i_1 - 16]) | 0)) | 0;
            }
            for (i_1 = 0; i_1 < 64; i_1++) {
                t1 =
                    ((((((e >>> 6) | (e << (32 - 6))) ^
                        ((e >>> 11) | (e << (32 - 11))) ^
                        ((e >>> 25) | (e << (32 - 25)))) +
                        ((e & f) ^ (~e & g))) |
                        0) +
                        ((h + ((K[i_1] + w[i_1]) | 0)) | 0)) |
                    0;
                t2 =
                    ((((a >>> 2) | (a << (32 - 2))) ^
                        ((a >>> 13) | (a << (32 - 13))) ^
                        ((a >>> 22) | (a << (32 - 22)))) +
                        ((a & b) ^ (a & c) ^ (b & c))) |
                    0;
                h = g;
                g = f;
                f = e;
                e = (d + t1) | 0;
                d = c;
                c = b;
                b = a;
                a = (t1 + t2) | 0;
            }
            h0 = (h0 + a) | 0;
            h1 = (h1 + b) | 0;
            h2 = (h2 + c) | 0;
            h3 = (h3 + d) | 0;
            h4 = (h4 + e) | 0;
            h5 = (h5 + f) | 0;
            h6 = (h6 + g) | 0;
            h7 = (h7 + h) | 0;
            off += 64;
            len -= 64;
        }
    }
    blocks(m);
    var i,
        bytesLeft = m.length % 64,
        bitLenHi = (m.length / 0x20000000) | 0,
        bitLenLo = m.length << 3,
        numZeros = bytesLeft < 56 ? 56 : 120,
        p = m.slice(m.length - bytesLeft, m.length);
    p.push(0x80);
    for (i = bytesLeft + 1; i < numZeros; i++) {
        p.push(0);
    }
    p.push((bitLenHi >>> 24) & 0xff);
    p.push((bitLenHi >>> 16) & 0xff);
    p.push((bitLenHi >>> 8) & 0xff);
    p.push((bitLenHi >>> 0) & 0xff);
    p.push((bitLenLo >>> 24) & 0xff);
    p.push((bitLenLo >>> 16) & 0xff);
    p.push((bitLenLo >>> 8) & 0xff);
    p.push((bitLenLo >>> 0) & 0xff);
    blocks(p);
    return [
        (h0 >>> 24) & 0xff,
        (h0 >>> 16) & 0xff,
        (h0 >>> 8) & 0xff,
        (h0 >>> 0) & 0xff,
        (h1 >>> 24) & 0xff,
        (h1 >>> 16) & 0xff,
        (h1 >>> 8) & 0xff,
        (h1 >>> 0) & 0xff,
        (h2 >>> 24) & 0xff,
        (h2 >>> 16) & 0xff,
        (h2 >>> 8) & 0xff,
        (h2 >>> 0) & 0xff,
        (h3 >>> 24) & 0xff,
        (h3 >>> 16) & 0xff,
        (h3 >>> 8) & 0xff,
        (h3 >>> 0) & 0xff,
        (h4 >>> 24) & 0xff,
        (h4 >>> 16) & 0xff,
        (h4 >>> 8) & 0xff,
        (h4 >>> 0) & 0xff,
        (h5 >>> 24) & 0xff,
        (h5 >>> 16) & 0xff,
        (h5 >>> 8) & 0xff,
        (h5 >>> 0) & 0xff,
        (h6 >>> 24) & 0xff,
        (h6 >>> 16) & 0xff,
        (h6 >>> 8) & 0xff,
        (h6 >>> 0) & 0xff,
        (h7 >>> 24) & 0xff,
        (h7 >>> 16) & 0xff,
        (h7 >>> 8) & 0xff,
        (h7 >>> 0) & 0xff,
    ];
}

// Reference for PBKDF2: https://en.wikipedia.org/wiki/PBKDF2#Key_derivation_process
function PBKDF2_HMAC_SHA256(password, salt, iterations, dkLen) {
    // compress password if it's longer than hash block length
    var passwordString = password.length <= 64 ? password : SHA256(password);
    var password = new Uint8Array(passwordString.length);
    for (var i = 0; i < passwordString.length; i++) {
        password[i] = passwordString[i].charCodeAt(0); // assume ascii because I'm lazy 🥺
    }

    // outerKey = password ^ opad
    var outerKey = new Array(64); // can't be TypedArray because it needs .concat()
    for (i = 0; i < 64; i++) outerKey[i] = 0x5c;
    for (i = 0; i < password.length; i++) outerKey[i] ^= password[i];

    var dk = new Uint8Array(dkLen / 8);
    for (var block = 1; block <= Math.max(1, dkLen / 256); block++) {
        var t = new Uint8Array(32);
        // saltOrPrevious = salt || counter
        var saltOrPrevious = new Uint8Array(salt.length + 4);
        var blockArray = INT32_BE(block);
        for (var i = 0; i < salt.length; i++) {
            saltOrPrevious[i] = salt[i].charCodeAt(0); // assume ascii because I'm lazy 🥺
        }
        for (var i = 0; i < 4; i++) {
            saltOrPrevious[i + salt.length] = blockArray[i];
        }
        for (var iter = 0; iter < iterations; iter++) {
            var innerLen = 64 + saltOrPrevious.length;
            var inner = new Array(innerLen); // can't be TypedArray because SHA_256 needs .push()
            var i;
            // inner = (password ^ ipad) || saltOrPrevious
            for (i = 0; i < 64; i++) {
                inner[i] = 0x36;
            }
            for (i = 0; i < password.length; i++) {
                inner[i] ^= password[i];
            }
            for (i = 0; i < saltOrPrevious.length; i++) {
                inner[64 + i] = saltOrPrevious[i];
            }

            // output blocks = SHA256(outerKey || SHA256(inner)) ...
            var u = SHA256(outerKey.concat(SHA256(inner)));
            saltOrPrevious = u;
            for (i = 0; i < 32; i++) {
                t[i] ^= u[i];
            }
        }
        for (var i = 0; i < 32; i++) {
            dk[(block - 1) * 32 + i] = t[i];
        }
    }
    return TRIM_ARRAY(dk, dkLen);
}
