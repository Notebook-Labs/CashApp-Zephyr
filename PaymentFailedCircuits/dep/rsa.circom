// SPDX-License-Identifier: GPL-3.0-only
// This file is derived from doubleblind-xyz/circom-rsa.
// Original work can be found at https://github.com/doubleblind-xyz/circom-rsa/blob/master/circuits/fp.circom.
// We have adapted the code to implement EMSA-PKCS1-v1_5-ENCODE which is the standard used in DKIM rather than the SSH standard implemented by doubleblind-xyz.

pragma circom 2.0.3;

include "./fp.circom";

/** 
 * Computes base^65537 mod modulus
 * Does not necessarily reduce fully mod modulus (the answer could be
 * too big by a multiple of modulus)
 * This just does repeated squaring, and uses the fact that 65537 = 2^16 + 1
 */
template FpPow65537Mod(n, k) {
    signal input base[k];
    // Exponent is hardcoded at 65537
    signal input modulus[k];
    signal output out[k];

    component doublers[16];
    component adder = FpMul(n, k);
    for (var i = 0; i < 16; i++) {
        doublers[i] = FpMul(n, k);
    }

    for (var j = 0; j < k; j++) {
        adder.p[j] <== modulus[j];
        for (var i = 0; i < 16; i++) {
            doublers[i].p[j] <== modulus[j];
        }
    }
    for (var j = 0; j < k; j++) {
        doublers[0].a[j] <== base[j];
        doublers[0].b[j] <== base[j];
    }

    // use the doublers to compute base^2^16
    for (var i = 0; i + 1 < 16; i++) {
        for (var j = 0; j < k; j++) {
            doublers[i + 1].a[j] <== doublers[i].out[j];
            doublers[i + 1].b[j] <== doublers[i].out[j];
        }
    }
    // compute base^65537 = base^2^16 * base
    for (var j = 0; j < k; j++) {
        adder.a[j] <== base[j];
        adder.b[j] <== doublers[15].out[j];
    }
    for (var j = 0; j < k; j++) {
        out[j] <== adder.out[j];
    }
}

/** 
 * This template implements EMSA-PKCS1-v1_5-ENCODE (M, emLen) which is the padding used for RSA in dkim signatures
 * https://tools.ietf.org/html/rfc8017#section-9.2
 * EM = 0x00 || 0x01 || PS || 0x00 || T
 * keyLenBytes is the length of the RSA key in bytes
 */
template RSAPad(n, k, keyLenBytes) {

    var baseLen = 408; // length of shaHash + algorithm identifier in bits
    assert(baseLen + 8 + 65 <= n*k);
    var baseLenBytes = 51; // 51 * 8 = 408

    var msgLen = 256;
    var ffPadding = (keyLenBytes - 3 - baseLenBytes) * 8; // ffPadding is a length in bits
    assert(ffPadding >= 64); // The RFC guarantees at least 8 octets of 0xff padding.

    signal input sha[msgLen];
    signal output paddedMessage[k];

    signal paddedMessageBits[n*k];

    // T
    for (var i = 0; i < msgLen; i++) {
        paddedMessageBits[i] <== sha[i];
    }

    for (var i = msgLen; i < baseLen; i++) {
        paddedMessageBits[i] <== (0x3031300d060960864801650304020105000420 >> (i - msgLen)) & 1;
    }

    // 0x00
    for (var i = baseLen; i < baseLen + 8; i++) {
        paddedMessageBits[i] <== 0;
    }

    // PS + 0x01
    for (var i = baseLen + 8; i < baseLen + 8 + ffPadding + 1; i++) {
        paddedMessageBits[i] <== 1;
    }

    // 0x00
    // n*k - 8*keyLenBytes is just additional 0's added for when we convert to bigNum representation
    for (var i = baseLen + 8 + ffPadding + 1; i < n*k; i++) {
        paddedMessageBits[i] <== 0;
    }

    component paddedMessageB2n[k];
    for (var i = 0; i < k; i++) {
        paddedMessageB2n[i] = Bits2Num(n); // n is bounded by 122 so its safe
        for (var j = 0; j < n; j++) {
            paddedMessageB2n[i].in[j] <== paddedMessageBits[i*n+j];
        }
        paddedMessage[i] <== paddedMessageB2n[i].out;
    }
}

/**
 * This template verifies an RSA signature
 * It first gets the padded message from the base message
 * It then calculates signature^65537 mod (modulus)
 * Finally it checks the two outputs are equal
 * 70k constraints per signature verification
 */
template RSAVerify65537(n, k, keyLenBytes) {
    signal input signature[k];
    signal input modulus[k];
    signal input baseMessage[256]; // output of sha hash

    //
    // Get the padding
    //

    component padder = RSAPad(n, k, keyLenBytes);

    // flipped bits of sha hash
    for (var i = 0; i < 256; i++) {
         padder.sha[i] <== baseMessage[255-i];
    }

    // 
    // Compute signature^65537 mod (modulus)
    //

    // Check that the signature is in proper form and reduced mod modulus.
    // This is to ensure that fp mul will work
    component signatureRangeCheck[k];
    component bigLessThan = BigLessThan(n, k); // this is safe as signature and modulus are range checked
    
    for (var i = 0; i < k; i++) {
        
        bigLessThan.a[i] <== signature[i];
        bigLessThan.b[i] <== modulus[i];
    }
    bigLessThan.out === 1;

    component bigPow = FpPow65537Mod(n, k);
    for (var i = 0; i < k; i++) {
        bigPow.base[i] <== signature[i];
        bigPow.modulus[i] <== modulus[i];
    }

    //
    // Check equality 
    // 
    
    // By construction of the padding, the padded message is necessarily
    // smaller than the modulus. Thus, we don't have to check that bigPow is fully reduced.
    for (var i = 0; i < k; i++) {
        bigPow.out[i] === padder.paddedMessage[i];
    }
}

// component main = RSAVerify65537(114, 9, 128);
