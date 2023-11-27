pragma circom 2.0.3;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/gates.circom";
include "../dep/extract.circom";

/** 
 * This template extracts the name from the body and checks that it's formatted correctly
 * 3355 constraints]
 */
template NameRegex(msgBytes, maxName) {
    // msgBytes = nameRange + minName
    signal input in[msgBytes];

    signal input start;
    signal input len;

    assert(msgBytes < 65536); // because we use LessThan(16) gates to compare indices

    // check all elements of the input except for the name
    component eq[2][msgBytes];
    component lt[2][msgBytes];

    for (var i = 0; i < msgBytes; i++) {

        // \r
        eq[0][i] = IsEqual();
        eq[0][i].in[0] <== in[i];
        eq[0][i].in[1] <== 13;

        // \n
        eq[1][i] = IsEqual();
        eq[1][i].in[0] <== in[i];
        eq[1][i].in[1] <== 10;

        // this is 1 when index >= len + start
        // the idea is that we should ignore the indices greater than len + start 
        // because we don't need to assert anything 
        // about these characters
        lt[0][i] = LessThan(16);
        lt[0][i].in[0] <== len + start - 1;
        lt[0][i].in[1] <== i;

        // this is 1 when index < start. Again, the
        // check below won't constrain the type of character for indices of in before 
        // start
        lt[1][i] = LessThan(16);
        lt[1][i].in[0] <== i;
        lt[1][i].in[1] <== start;
        
        // if they are both false this will fail
        // eq[0][i].out, eq[1][i].out are mutually exclusive and so is lt[0][i].out, lt[1][i].out
        0 === (eq[0][i].out + eq[1][i].out) * (1 - lt[0][i].out - lt[1][i].out);
    }

    // extract characters between start and len + start
    signal masked[msgBytes];
    for (var i = 0; i < msgBytes; i++) {
        masked[i] <== in[i] * (1 - lt[0][i].out - lt[1][i].out);
    }

    // parse out the name using a double array. We extract maxName, the range of the start index is
    // msgBytes - maxName (i.e. any index in in[msgBytes] could be part of name).
    component nameExtract = UncertaintyExtraction(msgBytes - maxName, maxName, 0, msgBytes);
    nameExtract.indicatorLen <== start;
    for (var i = 0; i < msgBytes; i++) {
        nameExtract.in[i] <== masked[i];
    }
    
    signal output out[maxName];
    for (var i = 0; i < maxName; i++){
        out[i] <== nameExtract.out[i];
    }
}

