// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/gates.circom";

/** 
 * This template extracts the amount from the body and checks that it's formatted correctly
 * 6600 constraints
 */
template AmountRegex(msgBytes) {
    // msgBytes = amountRange + minAmount 
    signal input in[msgBytes];

    signal input start;
    signal input len;

    signal output out;

    assert(msgBytes < 65536); // because we use LessThan(16) gates to compare indices

    // first chars are irrelevant, then should be of the format [0-9]*.[0-9][0-9]
    // can check a regex without needing states
    component lt[4][msgBytes];
    component eq[2][msgBytes];
    component and[2][msgBytes];
    signal revealIndicator[msgBytes];

    // if there is no full stop
    signal fullStop[msgBytes + 1];
    fullStop[0] <== 0;

    for (var i = 0; i < msgBytes; i++) {
        // isolate values in the range of indices: start - 1 < i < start - 3
        lt[0][i] = LessThan(16);
        lt[0][i].in[0] <== start - 1;
        lt[0][i].in[1] <== i;

        lt[1][i] = LessThan(16);
        lt[1][i].in[0] <== i;
        lt[1][i].in[1] <== start + len;

        and[0][i] = AND();
        and[0][i].a <== lt[0][i].out;
        and[0][i].b <== lt[1][i].out;

        // check the value of the element is between 0-9
        lt[2][i] = LessThan(8);
        lt[2][i].in[0] <== 47;
        lt[2][i].in[1] <== in[i];

        lt[3][i] = LessThan(8);
        lt[3][i].in[0] <== in[i];
        lt[3][i].in[1] <== 58;

        and[1][i] = AND();
        and[1][i].a <== lt[2][i].out;
        and[1][i].b <== lt[3][i].out;

        // check for full stop
        eq[0][i] = IsEqual();
        eq[0][i].in[0] <== in[i];
        eq[0][i].in[1] <== 46;

        // check for comma
        eq[1][i] = IsEqual();
        eq[1][i].in[0] <== in[i];
        eq[1][i].in[1] <== 44;
        
        and[0][i].out * (1 - and[1][i].out - eq[0][i].out - eq[1][i].out) === 0;

        revealIndicator[i] <== and[0][i].out * and[1][i].out; // position and value

        fullStop[i + 1] <== fullStop[i] + eq[0][i].out * and[0][i].out;
    }

    // use the indicator to parse the amount into an output
    signal amount[msgBytes + 2];
    amount[0] <== 0;
    for (var i = 0; i < msgBytes; i++) {
        amount[i + 1] <== amount[i] + revealIndicator[i] * (9 * amount[i] + in[i] - 48);
    }

    component isFullStop = IsZero();  
    isFullStop.in <== fullStop[msgBytes];

    amount[msgBytes + 1] <== amount[msgBytes] + isFullStop.out * 99 * amount[msgBytes];

    out <== amount[msgBytes + 1];
}
