// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/gates.circom";

/** 
 * This function unpacks a byte array into a bigint. 
 * Output is constrained because this is linear
 * Ensure the input is sufficiently small to not overflow
 */
function Bytes2Packed(len, in) {
    var result = 0;

    for (var i = 0; i < len; i++) {
        // each byte we multiple by 2^8
        result += in[i] * (2 ** (i * 8));
    }

    return result;
}
