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
    var inBits = modBitLen + 512; // add a block for padding

    component shaMod = Sha256(inBits);
    component modBits0[k];

    // Pack modulus 0
    for (var j = 0; j < k - 1; j++) {
        modBits0[j] = Num2Bits(n);
        modBits0[j].in <== modulus0[j];
        for (var i = 0; i < n; i++) {
            shaMod.in[n * j + i] <== modBits0[j].out[n - 1 - i];
        }
    }

    // bit length of the last array value of modulus 0 and 1
    var remBits = keyLenBytes * 8 - n * (k - 1);
    modBits0[k - 1] = Num2Bits(remBits);
    modBits0[k - 1].in <== modulus0[k - 1];
    for (var i = 0; i < remBits; i++) {
        shaMod.in[n * (k - 1) + i] <== modBits0[k - 1].out[remBits - 1 - i];
    }

    component lenBits = Num2Bits(14); // max value of len is 512 * 16 = 2^13
    lenBits.in <== inBits - 512;

    // Adding sha padding
    shaMod.in[modBitLen] <== 1;
    for (var i = 1; i < 498; i++) {
        shaMod.in[modBitLen + i] <== 0;
    }

    // flip the bits of lenBits.out because sha256 treats the most sig bit as the one at index 0
    // and Num2Bits has the least significant bit as the one at index 0
    for (var i = 0; i < 14; i++) {
        shaMod.in[inBits - 1 - i] <== lenBits.out[i];
    }

    // output the hash
    for (var i = 0; i < 256; i++) {
        out[i] <== shaMod.out[i];
    }
}

/** 
 * This template calculates the sha256 hash of the concatenated moduli
 * Used to commit to the keys used to verify the email. Packs the keys and then hashes them
 * This assumes that n, k are bounded so that the Num2Bits is safe
 */
template ModulusSha(n, k, keyLenBytes) {
    signal input modulus0[k];
    signal input modulus1[k];
    signal output out[256];

    assert(keyLenBytes <= 512); // for Num2Bits
    assert(keyLenBytes % 64 == 0);
    
    var modBitLen = keyLenBytes * 8;
    var inBits = modBitLen * 2 + 512; // add a block for padding

    component shaMod = Sha256(inBits);
    component modBits0[k];
    component modBits1[k];

    // Pack modulus 0
    for (var j = 0; j < k - 1; j++) {
        modBits0[j] = Num2Bits(n);
        modBits0[j].in <== modulus0[j];
        for (var i = 0; i < n; i++) {
            shaMod.in[n * j + i] <== modBits0[j].out[n - 1 - i];
        }
    }

    // bit length of the last array value of modulus 0 and 1
    var remBits = keyLenBytes * 8 - n * (k - 1);
    modBits0[k - 1] = Num2Bits(remBits);
    modBits0[k - 1].in <== modulus0[k - 1];
    for (var i = 0; i < remBits; i++) {
        shaMod.in[n * (k - 1) + i] <== modBits0[k - 1].out[remBits - 1 - i];
    }

    // Pack modulus 1
    for (var j = 0; j < k - 1; j++) {
        modBits1[j] = Num2Bits(n);
        modBits1[j].in <== modulus1[j];
        for (var i = 0; i < n; i++) {
            shaMod.in[modBitLen + n * j + i] <== modBits1[j].out[n - 1 - i];
        }
    }

    modBits1[k - 1] = Num2Bits(remBits);
    modBits1[k - 1].in <== modulus1[k - 1];
    for (var i = 0; i < remBits; i++) {
        shaMod.in[modBitLen + n * (k - 1) + i] <== modBits1[k - 1].out[remBits - 1 - i];
    }

    component lenBits = Num2Bits(14); // max value of len is 512 * 16 = 2^13
    lenBits.in <== inBits - 512;

    // Adding sha padding
    shaMod.in[2 * modBitLen] <== 1;
    for (var i = 1; i < 498; i++) {
        shaMod.in[2 * modBitLen + i] <== 0;
    }

    // flip the bits of lenBits.out because sha256 treats the most sig bit as the one at index 0
    // and Num2Bits has the least significant bit as the one at index 0
    for (var i = 0; i < 14; i++) {
        shaMod.in[inBits - 1 - i] <== lenBits.out[i];
    }

    // output the hash
    for (var i = 0; i < 256; i++) {
        out[i] <== shaMod.out[i];
    }
}
