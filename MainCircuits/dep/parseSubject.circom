// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "./utf8.circom";
include "./utf8End.circom";
include "./variableCopy.circom";

/** 
 * 
 */
template ParseSubject(maxBytes, numRounds) { 

    signal input in[maxBytes];

    // we run 9 rounds of identify index of utf8 encoded section and shift array

    component utf8[numRounds];
    component variableCopy[numRounds + 1];

    signal shift[numRounds + 2][maxBytes];

    for (var j = 0; j < maxBytes; j++) {
        shift[0][j] <== in[j];
    }

    variableCopy[0] = VariableCopy(maxBytes, 10); //first UTF8 occurence is 10 bytes long
    utf8[0] = UTF8(maxBytes, 0);
    for (var j = 1; j < numRounds; j++) {
        variableCopy[j] = VariableCopy(maxBytes, 13);
        utf8[j] = UTF8(maxBytes, 1);
    }
    variableCopy[numRounds] = VariableCopy(maxBytes, 2);

    // identify and extract patterns of the form ?= =?UTF-8?Q?
    for (var i = 0; i < numRounds; i++) {

        for (var j = 0; j < maxBytes; j++) {
            utf8[i].in[j] <== shift[i][j];
        }

        variableCopy[i].len <== utf8[i].index;

        for (var j = 0; j < maxBytes; j++) {
            variableCopy[i].in[j] <== shift[i][j];
        }
        for (var j = 0; j < maxBytes; j++) {
            shift[i+1][j] <== variableCopy[i].out[j];
        }
    }

    // remove the final potential ?=
    component utf8End = UTF8End(maxBytes);
    for (var j = 0; j < maxBytes; j++) {
        utf8End.in[j] <== shift[numRounds][j];
    }

    variableCopy[numRounds].len <== utf8End.index;

    for (var j = 0; j < maxBytes; j++) {
        variableCopy[numRounds].in[j] <== shift[numRounds][j];
    }
    for (var j = 0; j < maxBytes; j++) {
        shift[numRounds+1][j] <== variableCopy[numRounds].out[j];
    }

    // now we want to replace underscores with SPACE
    component underscore[maxBytes];

    signal output subject[maxBytes];

    for (var i = 0; i < maxBytes; i++) {
        underscore[i] = IsZero();
        underscore[i].in <== shift[numRounds + 1][i] - 95;
        
        subject[i] <== underscore[i].out * 32 + shift[numRounds + 1][i] * (1 - underscore[i].out); 
    }
}

//component main = ParseSubject(450);