// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/gates.circom";
include "../../dep/extract.circom";

/** 
 * This template extracts the username from the body and checks that it's formatted correctly
 * 3355 constraints]
 */
template UsernameRegex(msgBytes, maxUsername) {
    // msgBytes = usernameRange + minusername
    signal input in[msgBytes];

    signal input start;
    signal input len;

    assert(msgBytes < 65536); // because we use LessThan(16) gates to compare indices

    // check all elements of the input in the correct indices are in the regex (a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0-9 )
    component eq[3][msgBytes];
    component lt[8][msgBytes];
    component and[3][msgBytes];

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


        // this is 1 when index >= len + start
        // the idea is that we should ignore the indices greater than len + start 
        // because we don't need to assert anything 
        // about these characters
        lt[6][i] = LessThan(16);
        lt[6][i].in[0] <== len + start - 1;
        lt[6][i].in[1] <== i;

        // this is 1 when index < start. Again, the
        // check below won't constrain the type of character for indices of in before 
        // start
        lt[7][i] = LessThan(16);
        lt[7][i].in[0] <== i;
        lt[7][i].in[1] <== start;
        
        // if they are both false this will fail
        0 === (1 - and[0][i].out - and[1][i].out - and[2][i].out) * (1 - lt[6][i].out - lt[7][i].out);
    }

    // extract characters between start and len + start
    signal masked[msgBytes];
    for (var i = 0; i < msgBytes; i++) {
        masked[i] <== in[i] * (1 - lt[6][i].out - lt[7][i].out);
    }

    // parse out the username using a double array. We extract maxUsername, the range of the start index is
    // msgBytes - maxUsername (i.e. any index in in[msgBytes] could be part of username).
    component usernameExtract = UncertaintyExtraction(msgBytes - maxUsername, maxUsername, 0, msgBytes);
    usernameExtract.indicatorLen <== start;
    for (var i = 0; i < msgBytes; i++) {
        usernameExtract.in[i] <== masked[i];
    }
    
    signal output out[maxUsername];
    for (var i = 0; i < maxUsername; i++){
        out[i] <== usernameExtract.out[i];
    }
}

