// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/comparators.circom";

/**
 *
 * This function is inspired by the Base64Lookup implementation in zk-email.
 * While it serves a similar purpose, this version has been independently developed to achieve significant speedups and greater flexibility.
 * Original work can be found at https://github.com/zkemail/zk-email-verify/blob/main/packages/circuits/helpers/base64.circom.
 *
 * This template converts from the ascii value to the base64 value of the character
 * In base 64 we have:
 * 0-25: A-Z (65-90)
 * 26-51: a-z (97-122)
 * 52-61: 0-9 (48-57)
 * 62: + (43)
 * 63: / (47)
 * padding: = (61)
 * So this function would convert c => 2
 *
 * We use two signals uc (upper case) and lc (lower case) to determine if the input is a number, lowercase letter, uppercase letter or +, /, =
 * We then use these indicators to create a linear map from the ascii value to a value in the range 1-26 in the less than case and 5-30 in the greater than case
 * Note that this transformation is complete in that if the right signal is specified the comparison will pass, furthermore the transformation is safe in that regardless
 * of the signals, +, /, = will fail and if the wrong signal is passed it will fail as seen below
 * 
 * Less Than: in - 31 - 65 * lc - 33 * uc
 *  
 * Number specified: lc = 0, uc = 0
 * 0-9: (48-57) -> 17-26  PASS
 * A-Z: (65-90) -> 34-59  FAIL as always > 31 so it will fail the Num2Bits(5) (range check) inside the less than
 * a-z: (97-122) -> 68-93 FAIL as always > 31 so it will fail the Num2Bits(5) (range check) inside the less than
 * =: (61) -> 31 FAIL as its greater than 26
 * 
 * Lower Case specified: lc = 1, uc = 0
 * a-z: (97-122) -> 1-26 PASS
 * 
 * Upper Case specified: lc = 0, uc = 1
 * A-Z: (65-90) -> 1-26 PASS
 * a-z (97-122) -> 33-58 FAIL as it will fail the range check Num2Bits(5)
 * 
 * Greatet Than: in - 43 - 49 * lc - 17 * uc
 * 
 * Number specified: lc = 0, uc = 0
 * 0-9: (48-57) -> 5-14  PASS
 * +: (43) -> 0 FAIL as it's <= 4
 * /: (47) -> 4 FAIL as it's <= 4
 * 
 * Lower Case specified: lc = 1, uc = 0
 * a-z: (97-122) -> 5-30 PASS
 * A-Z: (65-90) -> -27-(-2) FAIL as it's <= 4
 * 0-9: (48-57) -> -44-(-35) FAIL as it will fail the range check Num2Bits(5)
 * +: (43) -> -48 FAIL as it will fail the range check Num2Bits(5)
 * /: (47) -> -44 FAIL as it will fail the range check Num2Bits(5)
 * =: (61) -> -30 FAIL as it's <= 4
 * 
 * Upper Case specified: lc = 0, uc = 1
 * A-Z: (65-90) -> 5-30 PASS
 * 0-9: (48-57) -> -12-(-3) FAIL as it's <= 4
 * +: (43) -> -17 FAIL as it's <= 4
 * /: (47) -> -13 FAIL as it's <= 4
 * =: (61) -> 1 FAIL as it's <= 4
 */
template Base64Lookup() {
    signal input in;
    signal output out;

    //whether or not the input is a lower case letter
    //lc is 0 or 1. If lc is 1 -> sum will only be incremented if the input is in the range of a-z. Setting lc wrong will mean
    // the circuit will fail the check 'range + equalPlus.out + equalSlash.out + equalEqual.out === 1;'
    signal lc <-- (in < 123 && in > 96) ? 1 : 0;
    0 === lc * (1 - lc);

    //whether or not the signal is A-Z
    signal uc <-- (in < 91 && in > 64) ? 1 : 0;
    0 === uc * (1 - uc);

    0 === uc * lc; //can't both be 1

    // ['A', 'Z'], ['a', 'z'] and ['0', '9']
    component le = LessThan(5);
    le.in[0] <== in - 31 - 65 * lc - 33 * uc; //maps A-Z to 1-26, a-z to 1-26, 0-9 to 17-26, + to 12, / to 16 and = to 30
    le.in[1] <== 27;

    component ge = GreaterThan(5);
    ge.in[0] <== in - 43 - 49 * lc - 17 * uc; //maps A-Z to 5-30, a-z to 5-30 and 0-9 to 5-14, + to 0, / to 4 and = to 18
    ge.in[1] <== 4;

    signal range <== ge.out * le.out; // 1 if in is in range, 0 otherwise

    // '+'
    component equalPlus = IsZero();
    equalPlus.in <== in - 43;

    // '/'
    component equalSlash = IsZero();
    equalSlash.in <== in - 47;

    // '='
    component equalEqual = IsZero(); //base64 value of 0 
    equalEqual.in <== in - 61;

    // ensure that input was valid base64
    range + equalPlus.out + equalSlash.out + equalEqual.out === 1;


    // signal sum <== range * (in + 4 - 75 * lc - 69 * uc);
    // signal sumPlus <== sum + equalPlus.out * (in + 19);
    // signal sumSlash <== sumPlus + equalSlash.out * (in + 16);

    // Little optimisation of the above lines to save a constraint
    signal sum0 <== range * (in + 4 - 75 * lc - 69 * uc);
    out <== in * (equalSlash.out + equalPlus.out) + 16 * equalSlash.out + 19 * equalPlus.out + sum0;
}

/**
 *
 * This function is inspired by the Base64Decode implementation in zk-email.
 * While it serves a similar purpose, this version has been independently developed to achieve significant speedups and greater flexibility.
 * Original work can be found at https://github.com/zkemail/zk-email-verify/blob/main/packages/circuits/helpers/base64.circom.
 *
 * This template takes an ascii string representing a base64 value and decodes it and outputs a binary array
 * Here M is 44 due to padding
 */
template Base64Decode(M) {

    // the input has been bound checked so it's safe to use
    signal input in[M];
    signal output out[6*M];

    component translate[M];
    component bitsIn[M];

    for (var i = 0; i < M; i++) {

        // convert out of base64 into a numer and then into binary
        bitsIn[i] = Num2Bits(6);
        translate[i] = Base64Lookup();
        translate[i].in <== in[i];
        translate[i].out ==> bitsIn[i].in;

        for (var j = 0; j < 6; j++) {
            out[6*i+j] <== bitsIn[i].out[5-j];
        }
    }

    //verify positions of the equal signs to ensure they're only at the end of the string
    //check that after the first occurence of an equals sign, all later occurences are also an equals sign
    component equalsChecks[M];
    signal seenAnEquals[M + 1]; //0 if not seen an equals sign, otherwise is number of 0's seen
    seenAnEquals[0] <== 0;
    for (var i = 0; i < M; i++) {
        equalsChecks[i] = IsZero(); //base64 value of 0 
        equalsChecks[i].in <== in[i] - 61;
        seenAnEquals[i+1] <== seenAnEquals[i] + equalsChecks[i].out;
        //if seenAnEquals !=0 - constrain equalsCheck to be 1
        (1 - equalsChecks[i].out) * seenAnEquals[i+1] === 0;
    }

}

/**
 * This template takes an ascii string representing a base64 value and decodes it and outputs a binary array.
 * This generalises Base64Decode to take strings of arbitrary length less than maxBytes and outputs an ASCII array.
 */
template Base64VariableDecode(maxBytes) {
    // the input has been bound checked so it's safe to use
    signal input in[maxBytes];
    signal input len; //we assume len < maxBytes 

    assert(maxBytes % 4 == 0); //for the last 3 cases

    //length of the outputted ascii. fixed at compile time
    var outLen = (6 * maxBytes) \ 8; 
    signal output out[outLen];

    component translate[maxBytes];
    component lt[maxBytes];
    for (var i = 0; i < maxBytes; i++) {
        lt[i] = LessThan(logCeil(maxBytes));
        lt[i].in[0] <== i;
        lt[i].in[1] <== len; //flag used to be +1

        // convert out of base64 into a numer and then into binary
        translate[i] = Base64Lookup();

        translate[i].in <== in[i] * lt[i].out + 61 * (1 - lt[i].out); //treats all values after len as an equals sign (so padding)
    }

    //verify positions of the equal signs to ensure they're only at the end of the string
    //check that after the first occurence of an equals sign, all later occurences are also an equals sign
    component equalsChecks[maxBytes];
    signal seenAnEquals[maxBytes + 1]; //0 if not seen an equals sign, otherwise is number of 0's seen
    seenAnEquals[0] <== 0;
    for (var i = 0; i < maxBytes; i++) {
        equalsChecks[i] = IsZero(); //base64 value of 0 
        equalsChecks[i].in <== (in[i] - 61) * lt[i].out;
        seenAnEquals[i+1] <== seenAnEquals[i] + equalsChecks[i].out;
        //if seenAnEquals !=0 - constrain equalsCheck to be 1
        (1 - equalsChecks[i].out) * seenAnEquals[i+1] === 0; 
    }

    component bitsIn[maxBytes];
    signal bits[6*maxBytes];
    for (var i = 0; i < maxBytes; i++) {
        bitsIn[i] = Num2Bits(6);
        translate[i].out ==> bitsIn[i].in;

        for (var j = 0; j < 6; j++) {
            bits[6*i+j] <== bitsIn[i].out[5-j];
        }
    }
    for (var i = 0; i < outLen; i++) {
        out[i] <== 128 * bits[8*i] + 64 * bits[8*i+1] + 32 * bits[8*i+2] + 16 * bits[8*i+3] + 8 * bits[8*i+4] + 4 * bits[8*i+5] + 2 * bits[8*i+6] + bits[8*i+7];
    }
}

