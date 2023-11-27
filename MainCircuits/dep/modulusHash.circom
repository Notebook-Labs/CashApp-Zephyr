// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/sha256/sha256.circom";


/** 
 * This template calculates the sha256 hash of one 2048 bit rsa key
 * Used to commit to the keys used to verify the email. Packs the keys and then hashes them
 * This assumes that n, k are bounded so that the Num2Bits is safe
 */
template ModulusShaSingle(n, k, keyLenBytes) {
    signal input modulus0[k];
    signal output out[256];

    assert(keyLenBytes <= 512); // for Num2Bits
    assert(keyLenBytes % 64 == 0);
    
    var modBitLen = keyLenBytes * 8;

    component shaMod = Sha256(modBitLen);
    component modBits0[k];

    // Pack modulus 0
    for (var j = 0; j < k - 1; j++) {
        modBits0[j] = Num2Bits(n);
        modBits0[j].in <== modulus0[j];
        for (var i = 0; i < n; i++) {
            shaMod.in[(modBitLen - 1) - (n * j + i)] <== modBits0[j].out[i];
        }
    }

    // bit length of the last array value of modulus 0 and 1
    var remBits = keyLenBytes * 8 - n * (k - 1);
    modBits0[k - 1] = Num2Bits(remBits);
    modBits0[k - 1].in <== modulus0[k - 1];
    for (var i = 0; i < remBits; i++) {
        shaMod.in[(modBitLen - 1) - (n * (k - 1) + i)] <== modBits0[k - 1].out[i];
    }

    // output the hash
    for (var i = 0; i < 256; i++) {
        out[i] <== shaMod.out[i];
    }
}

/** 
 * This template calculates the sha256 hash of the concatenated moduli
 * Used to commit to the keys used to verify the email. Packs the keys and then hashes them
 * This assumes that n, k are bounded so that the Num2Bits is safe. The keys are packed so 
 * that the most significant bit of modulus0 is the first bit of the input to sha256, and
 * similarly, the bits of modulus1 are arranged from most to least significant.
 */
template ModulusSha(n, k, keyLenBytes) {
    signal input modulus0[k];
    signal input modulus1[k];
    signal output out[256];

    assert(keyLenBytes <= 512); // for Num2Bits
    assert(keyLenBytes % 64 == 0);
    
    var modBitLen = keyLenBytes * 8;
    var inBits = modBitLen * 2;

    component shaMod = Sha256(inBits);
    component modBits0[k];
    component modBits1[k];

    // Pack modulus 0
    for (var j = 0; j < k - 1; j++) {
        modBits0[j] = Num2Bits(n);
        modBits0[j].in <== modulus0[j];
        for (var i = 0; i < n; i++) {
            shaMod.in[(modBitLen - 1) - (n * j + i)] <== modBits0[j].out[i];
        }
    }

    // bit length of the last array value of modulus 0 and 1
    var remBits = keyLenBytes * 8 - n * (k - 1);
    modBits0[k - 1] = Num2Bits(remBits);
    modBits0[k - 1].in <== modulus0[k - 1];
    for (var i = 0; i < remBits; i++) {
        shaMod.in[(modBitLen - 1) - (n * (k - 1) + i)] <== modBits0[k - 1].out[i];
    }

    // Pack modulus 1
    for (var j = 0; j < k - 1; j++) {
        modBits1[j] = Num2Bits(n);
        modBits1[j].in <== modulus1[j];
        for (var i = 0; i < n; i++) {
            shaMod.in[(2 * modBitLen - 1) - (n * j + i)] <== modBits1[j].out[i];
        }
    }

    modBits1[k - 1] = Num2Bits(remBits);
    modBits1[k - 1].in <== modulus1[k - 1];
    for (var i = 0; i < remBits; i++) {
        shaMod.in[(2 * modBitLen - 1) - (n * (k - 1) + i)] <== modBits1[k - 1].out[i];
    }

    // output the hash
    for (var i = 0; i < 256; i++) {
        out[i] <== shaMod.out[i];
    }
}