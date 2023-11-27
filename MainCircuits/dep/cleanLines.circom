// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "./endLine.circom";
include "./variableCopy.circom";

/** 
 * 
 */
template CleanLines(maxBytes, num) { 

    signal input in[maxBytes];

    // we run num rounds of identify index of end line encoded section and shift array

    component endLine[num];
    component variableCopy[num];

    signal shift[num+1][maxBytes];

    for (var j = 0; j < maxBytes; j++) {
        shift[0][j] <== in[j];
    }

    for (var j = 0; j < num; j++) {
        variableCopy[j] = VariableCopy(maxBytes, 3);
        endLine[j] = EndLine(maxBytes);
    }

    // identify and extract patterns of the form =\r\n
    for (var i = 0; i < num; i++) {

        for (var j = 0; j < maxBytes; j++) {
            endLine[i].in[j] <== shift[i][j];
        }

        variableCopy[i].len <== endLine[i].index;

        for (var j = 0; j < maxBytes; j++) {
            variableCopy[i].in[j] <== shift[i][j];
        }

        for (var j = 0; j < maxBytes; j++) {
            shift[i+1][j] <== variableCopy[i].out[j];
        }
    }

    signal output clean[maxBytes];

    for (var j = 0; j < maxBytes; j++) {
        clean[j] <== shift[num][j];
    }
}

//component main = CleanLines(400, 4);