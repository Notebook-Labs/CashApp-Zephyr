// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/gates.circom";

/**
 * This template is used to extract the body hash from the DKIM field of the header
 * The DKIM field is the last field of a header, therefore we look for the last occurence of bh= and extract
 * the base64 characters.
 * 54209 constraints
 */
template BodyHashRegex(msgBytes, lenShaB64) {
    signal input msg[msgBytes];

    var numBytes = msgBytes;

    assert(numBytes >= lenShaB64);
    
    signal in[numBytes];

    for (var i = 0; i < msgBytes; i++) {
        in[i] <== msg[i];
    }

    //
    // Run a DFA to identify all occurences of bh=
    // 

    signal output bodyHashOut[lenShaB64];

	component eq[4][numBytes];
	signal states[numBytes+1][4];

    states[0][0] <== 0;
    states[0][1] <== 0;
    states[0][2] <== 0;
    states[0][3] <== 0;

    // identify the occurences of bh= in the subject
	for (var i = 0; i < numBytes; i++) {

        // SPACE
		eq[0][i] = IsEqual();
		eq[0][i].in[0] <== in[i];
		eq[0][i].in[1] <== 32;
		states[i+1][0] <== eq[0][i].out;

		// b 
		eq[1][i] = IsEqual();
		eq[1][i].in[0] <== in[i];
		eq[1][i].in[1] <== 98;
		states[i+1][1] <== states[i][0] * eq[1][i].out;

		// h 
		eq[2][i] = IsEqual();
		eq[2][i].in[0] <== in[i];
		eq[2][i].in[1] <== 104;
		states[i+1][2] <== states[i][1] * eq[2][i].out;
	
		// = 
		eq[3][i] = IsEqual();
		eq[3][i].in[0] <== in[i];
		eq[3][i].in[1] <== 61;
		states[i+1][3] <== states[i][2] * eq[3][i].out;
	}

    //
    // Extract the index of the final bh=
    // 

    // need to get last occurence of bh= in the subject in case someone embedded it into
    // their email - so should loop backward
    // gets arrays bhIndex = [0, 0, 0, 0, 1, 0, 0, 0, ...] and bhSum = [1, 1, 1, 1, 0, 0, 0, 0, ...]
    signal bhSum[numBytes + 1];
    bhSum[numBytes] <== 0;
    signal bhIndex[numBytes + 1];
    bhIndex[numBytes] <== 0;
    for (var i = numBytes - 1; i >= 0; i--) {
        bhSum[i] <== bhSum[i+1] + states[i+1][3] * (1 - bhSum[i+1]);
        bhIndex[i] <== (1 - bhSum[i+1]) * states[i+1][3];
    }


    // extract the bh using the index in double array iterating through numBytes with no offset
    signal extendedIn[numBytes + lenShaB64 + 1];
    for (var i = 0; i < numBytes; i++) {
        extendedIn[i] <== in[i];
    }
    for (var i = numBytes; i < numBytes + lenShaB64 + 1; i++) {
        extendedIn[i] <== 0;
    }

    //
    // Extract the body hash
    // 

    // use double array method to extract the body hash
    signal bh[lenShaB64][numBytes];
    for (var i = 0; i < lenShaB64; i++) {
        bh[i][0] <== extendedIn[i+1] * bhIndex[0];
        for (var j = 1; j < numBytes; j++) {
            bh[i][j] <== extendedIn[i + j + 1] * bhIndex[j] +  bh[i][j - 1];
        }
    }

    for (var i = 0; i < lenShaB64; i++) {
        bodyHashOut[i] <== bh[i][numBytes - 1];
    }
}

// component main = BodyHashRegex(1024, 44);
