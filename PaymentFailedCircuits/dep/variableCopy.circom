// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/comparators.circom";

/** 
 * This template is takes an array of the form [var 1 | FIXED | var 2] and outputs [var 1 | var 2]
 * A len of 0 signifies we make no changes. Variable copy assumes that len is incremented by 1. 
 * (so a len of 1 corresponds to the first element in the array (at index 0)).
 */
template VariableCopy(maxBytes, fixLen) {
    signal input in[maxBytes];
    signal input len;

    signal output out[maxBytes];

    component eq[maxBytes - fixLen];
    signal sum[maxBytes - fixLen + 1];
    sum[0] <== 0;

    component isZero = IsZero();
    isZero.in <== len;

    for (var i = 0; i < maxBytes - fixLen; i++) {

        eq[i] = IsEqual();
        eq[i].in[0] <== len - 1 + isZero.out * maxBytes; // to account for the +1 shift
        eq[i].in[1] <== i; // as len is exactly the length we want to start 

        sum[i+1] <== sum[i] + eq[i].out;

        out[i] <== in[i] + sum[i+1] * (in[i + fixLen] - in[i]);

    }

    for (var i = maxBytes - fixLen; i < maxBytes; i++) {
        out[i] <== isZero.out * in[i];
    }
}
