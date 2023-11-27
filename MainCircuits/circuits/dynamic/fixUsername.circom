// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/gates.circom";
include "../../dep/extract.circom";

/** 
 * This template extracts the username from the body and checks that it's formatted correctly
 * 3355 constraints]
 */
template FixUsernameRegex(msgBytes) {
    // msgBytes = usernameRange + minusername
    signal input in[msgBytes];

    signal input len;

    assert(msgBytes < 65536); // because we use LessThan(16) gates to compare indices

    signal output out[msgBytes];

    // check all elements of the input in the correct indices are in the regex (a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0-9 )
    component eq[4][msgBytes];
    component lt[6][msgBytes];
    component and[3][msgBytes];

    signal sum[msgBytes+1];
    sum[0] <== 0;

    for (var i = 0; i < msgBytes; i++) {

        eq[3][i] = IsEqual();
        eq[3][i].in[0] <== len;
        eq[3][i].in[1] <== i;

        sum[i+1] <== sum[i] + eq[3][i].out;

        out[i] <== in[i] * (1 - sum[i+1]);
    }

    for (var i = 0; i < msgBytes; i++) {
        // check characters in the range A-Z
        lt[0][i] = LessThan(8);
        lt[0][i].in[0] <== 64;
        lt[0][i].in[1] <== in[i];

        lt[1][i] = LessThan(8);
        lt[1][i].in[0] <== in[i];
        lt[1][i].in[1] <== 91;

        and[0][i] = AND();
        and[0][i].a <== lt[0][i].out;
        and[0][i].b <== lt[1][i].out;

        // check characters in the range a-z
        lt[2][i] = LessThan(8);
        lt[2][i].in[0] <== 96;
        lt[2][i].in[1] <== in[i];

        lt[3][i] = LessThan(8);
        lt[3][i].in[0] <== in[i];
        lt[3][i].in[1] <== 123;

        and[1][i] = AND();
        and[1][i].a <== lt[2][i].out;
        and[1][i].b <== lt[3][i].out;

        // check the characters in the range 0-9
        lt[4][i] = LessThan(8);
        lt[4][i].in[0] <== 47;
        lt[4][i].in[1] <== in[i];

        lt[5][i] = LessThan(8);
        lt[5][i].in[0] <== in[i];
        lt[5][i].in[1] <== 58;

        and[2][i] = AND();
        and[2][i].a <== lt[4][i].out;
        and[2][i].b <== lt[5][i].out;
        
        // if they are both false this will fail
        0 === (1 - and[0][i].out - and[1][i].out - and[2][i].out) * (1 - sum[i+1]);
    }
}

