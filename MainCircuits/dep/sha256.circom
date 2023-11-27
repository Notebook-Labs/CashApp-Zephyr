// SPDX-License-Identifier: BUSL-1.1
// This function is inspired by Circomlib's sha256 and zk-email's sha256general templates.
// While it serves a similar purpose, this version has been independently developed to achieve speedups and flexibility.
// Original work can be found at https://github.com/iden3/circomlib/blob/master/circuits/sha256/sha256.circom and at https://github.com/zkemail/zk-email-verify/blob/main/packages/circuits/helpers/sha256general.circom.

pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/sha256/constants.circom";
include "../../node_modules/circomlib/circuits/sha256/sha256compression.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "./bigintFunc.circom";

/** 
 * This template is a modified version of the SHA256 circuit that allows specified length messages up to a max to all work via array indexing on the SHA256 compression circuit.
 * 31k constraints per 64 bytes of inputs
 */
template Sha256(maxBitsPadded) {
    // maxBitsPadded must be a multiple of 512
    assert(maxBitsPadded >= 512);
    assert(maxBitsPadded % 512 == 0);

    // known at compilation time so is exact
    var maxBitsPaddedBits = logCeil(maxBitsPadded);
    // more than enough, this will avoid any issues with the lessThan template
    assert(maxBitsPaddedBits <= 50);  

    // known at compilation time
    var maxBlocks = maxBitsPadded \ 512; // divide by 512

    component eq[maxBitsPadded];
    signal sum[maxBitsPadded+1];
    sum[0] <== 0;

    signal input paddedIn[maxBitsPadded];
    signal input inLenPaddedBits; // This is the padded length of the message pre-hash.

    signal output out[256];

    // get number of blocks in length
    signal inBlockIndex <-- inLenPaddedBits \ 512; // divide by 512
    inLenPaddedBits === inBlockIndex * 512; // check that the length is a multiple of 512 and constrain the value of inBlockIndex

    // We need to range check inLenPaddedBits to make sure it is less than maxBitsPaddedBits so that we can check it in a lessEqThan
    component inLenRangeCheck = Num2Bits(maxBitsPaddedBits); // this is safe
    inLenRangeCheck.in <== inLenPaddedBits;

    // ensure the input is less than the maxBitsPaddedBits
    component bitLengthVerifier = LessEqThan(maxBitsPaddedBits);  // this is safe
    bitLengthVerifier.in[0] <== inLenPaddedBits;
    bitLengthVerifier.in[1] <== maxBitsPadded;
    bitLengthVerifier.out === 1;

    component ha0 = H(0);
    component hb0 = H(1);
    component hc0 = H(2);
    component hd0 = H(3);
    component he0 = H(4);
    component hf0 = H(5);
    component hg0 = H(6);
    component hh0 = H(7);

    component sha256compression[maxBlocks];

    // run through the sha compression function
    for (var i=0; i<maxBlocks; i++) {

        sha256compression[i] = Sha256compression() ;

        if (i==0) {
            for (var k=0; k<32; k++ ) {
                sha256compression[i].hin[0*32+k] <== ha0.out[k];
                sha256compression[i].hin[1*32+k] <== hb0.out[k];
                sha256compression[i].hin[2*32+k] <== hc0.out[k];
                sha256compression[i].hin[3*32+k] <== hd0.out[k];
                sha256compression[i].hin[4*32+k] <== he0.out[k];
                sha256compression[i].hin[5*32+k] <== hf0.out[k];
                sha256compression[i].hin[6*32+k] <== hg0.out[k];
                sha256compression[i].hin[7*32+k] <== hh0.out[k];
            }
        } else {
            for (var k=0; k<32; k++ ) {
                sha256compression[i].hin[32*0+k] <== sha256compression[i-1].out[32*0+31-k];
                sha256compression[i].hin[32*1+k] <== sha256compression[i-1].out[32*1+31-k];
                sha256compression[i].hin[32*2+k] <== sha256compression[i-1].out[32*2+31-k];
                sha256compression[i].hin[32*3+k] <== sha256compression[i-1].out[32*3+31-k];
                sha256compression[i].hin[32*4+k] <== sha256compression[i-1].out[32*4+31-k];
                sha256compression[i].hin[32*5+k] <== sha256compression[i-1].out[32*5+31-k];
                sha256compression[i].hin[32*6+k] <== sha256compression[i-1].out[32*6+31-k];
                sha256compression[i].hin[32*7+k] <== sha256compression[i-1].out[32*7+31-k];
            }
        }

        for (var k=0; k<512; k++) {
            sha256compression[i].inp[k] <== paddedIn[i*512+k];
        }
    }

    for (var i = 0; i < maxBitsPadded; i++) {

        eq[i] = IsEqual();
        eq[i].in[0] <== inLenPaddedBits;
        eq[i].in[1] <== i;

        sum[i+1] <== sum[i] + eq[i].out;

        paddedIn[i] * sum[i+1] === 0;
    }

    // Select the correct compression output for the given length, instead of just the last one.
    component eqs[maxBlocks];
    signal sums[256][maxBlocks+1];

    for (var k=0; k<256; k++) {
        sums[k][0] <== 0;
    }

    // Find the output index and the corresponding bit in the sha blocks
    // iterate through the blocks. For each block index i, check if it's equal to inBlockIndex
    // If so, add the corresponding sha256compression[i].out to the sum.
    for (var i = 0; i < maxBlocks; i ++) {
        eqs[i] = IsEqual();
        eqs[i].in[0] <== i;
        eqs[i].in[1] <== inBlockIndex - 1;

        for (var k=0; k<256; k++) {
            sums[k][i+1] <== sums[k][i] + eqs[i].out * sha256compression[i].out[k];
        }
    }

    // output the final sums
    for (var k=0; k<256; k++) {
        out[k] <== sums[k][maxBlocks];
    }
}
