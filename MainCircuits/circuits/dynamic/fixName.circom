pragma circom 2.0.3;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/gates.circom";
include "../dep/extract.circom";

/** 
 * This template extracts the name from the body and checks that it's formatted correctly
 * 3355 constraints]
 */
template FixNameRegex(msgBytes) {
    // msgBytes = nameRange + minName
    signal input in[msgBytes];

    signal input len;

    assert(msgBytes < 65536); // because we use LessThan(16) gates to compare indices

    signal output out[msgBytes];

    // check all elements of the input are not escape characters
    component eq[3][msgBytes];

    signal sum[msgBytes+1];
    sum[0] <== 0;

    for (var i = 0; i < msgBytes; i++) {

        eq[0][i] = IsEqual();
        eq[0][i].in[0] <== len;
        eq[0][i].in[1] <== i;

        sum[i+1] <== sum[i] + eq[0][i].out;

        out[i] <== in[i] * (1 - sum[i+1]);
    }

    for (var i = 0; i < msgBytes; i++) {

        // \r
        eq[1][i] = IsEqual();
        eq[1][i].in[0] <== in[i];
        eq[1][i].in[1] <== 13;

        // \n
        eq[2][i] = IsEqual();
        eq[2][i].in[0] <== in[i];
        eq[2][i].in[1] <== 10;



        
        // if they are both false this will fail
        // eq[1][i].out, eq[2][i].out are mutually exclusive
        0 ===  (eq[1][i].out + eq[2][i].out) * (1 - sum[i+1]);
    }
}

