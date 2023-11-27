// SPDX-License-Identifier: GPL-3.0-only
// This file is derived from yi-sun/zk-attestor.
// Original work can be found at https://github.com/yi-sun/zk-attestor/blob/master/circuits/rlp.circom.

pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "./bigintFunc.circom";

/* 
 * Ensures that the signal inLen is in-between min and max inclusive. First uses Num2Bits
 * to range check that inLen is less than 2^n-1. It then uses LessThan gates to verify 
 * that inLen is greater than min and less than max. n should be set so that 2^n-1 > max.
 */
template MaxMinCheck(n, min, max) {
    signal input inLen;

    component numBits = Num2Bits(n);
    numBits.in <== inLen;

    component maxCheck = LessThan(n);
    maxCheck.in[0] <== inLen;
    maxCheck.in[1] <== max + 1;
    maxCheck.out === 1;

    component minCheck = LessThan(n);
    minCheck.in[0] <== min - 1;
    minCheck.in[1] <== inLen;
    minCheck.out === 1;
}


/*
 * This template is used to extract extractSize signals from an array of signals of size
 * maxBytes where the sub-array could be anywhere between the indicies minIdx and 
 * minIdx + extractSize + range. It takes in a signal indicatorLen, which is some value 
 * between 0 and range, and uses this to determine where the extracted value starts.
 * Inspired by https://github.com/yi-sun/zk-attestor/blob/f4f4b2268f7cf8a0e5ac7f2b5df06a61859f18ca/circuits/rlp.circom#L8
 * We explain this further in the documentation
 */
template UncertaintyExtraction(range, extractSize, minIdx, maxBytes) {
    signal input indicatorLen; // the length between minIdx and where the extracted value starts
    signal input in[maxBytes];

    signal output out[extractSize];

    assert(maxBytes >= minIdx + extractSize + range - 1); // to prevent out of bounds access

    var rangeBits = (logCeil(range) > 0) ? logCeil(range): 1; //so it doesnt break when name = 0

    // nInBits is logCeil of range
    component n2b = Num2Bits(rangeBits); // bound checked so it's safe
    n2b.in <== indicatorLen;

    //loops through the binary representation of indicatorLen. Each iteration it either rotates
    //the signals in shifts[rangeBits][range + extractSize] around by a power of 2 or not at all
    //when it rotates the signals, it maps signal at index i to index i - 2^idx % (range + extractSize)
    signal shifts[rangeBits][range + extractSize];
    for (var idx = 0; idx < rangeBits; idx++) {
        for (var j = 0; j < range + extractSize; j++) {
            if (idx == 0) {
                // n2b.out[idx] is either 1 or 0. Will shift the indices over by 1 << idx or not at all
	            var tempIdx = (j + (1 << idx)) % (range + extractSize); // fixed at compile time
                shifts[idx][j] <== n2b.out[idx] * (in[minIdx + tempIdx] - in[minIdx + j]) + in[minIdx + j];
            } else {
                var prevIdx = idx - 1;
                var tempIdx = (j + (1 << idx)) % (range + extractSize); // fixed at compile time
                // n2b.out[idx] either 1 or 0, will shift over the indices from shifts[prevIdx][j] by either 1 << idx or not at all
                shifts[idx][j] <== n2b.out[idx] * (shifts[prevIdx][tempIdx] - shifts[prevIdx][j]) + shifts[prevIdx][j];            
            }
        }
    }

    for (var idx = 0; idx < extractSize; idx++) {  
        out[idx] <== shifts[rangeBits - 1][idx];
        // check if the extracted value is the expected value 
    }
}
