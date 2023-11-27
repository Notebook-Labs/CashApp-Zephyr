// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/comparators.circom";

// will always return index + 1, so if the pattern was found right at the start it would return 1
template UTF8End(msgBytes) {

    signal input in[msgBytes];

    //
    // Run a DFA to identify the first occurence of ?=
    // 

	component eq[2][msgBytes];
	signal states[msgBytes+1][2];

    states[0][0] <== 0;
    states[0][1] <== 0;

    // identify the occurences of bh= in the subject
	for (var i = 0; i < msgBytes; i++) {

        // ?
		eq[0][i] = IsEqual();
		eq[0][i].in[0] <== in[i];
		eq[0][i].in[1] <== 63;
		states[i+1][0] <== eq[0][i].out;

		// = 
		eq[1][i] = IsEqual();
		eq[1][i].in[0] <== in[i];
		eq[1][i].in[1] <== 61;
		states[i+1][1] <== states[i][0] * eq[1][i].out;
	}

    //
    // Extract the index of the first ?=
    // 

    // gets arrays utfIndex = [0, 0, 0, 0, 1, 0, 0, 0, ...] and utfSum = [0, 0, 0, 1, 1, 1, 1, 1, ...]
    signal utfSum[msgBytes + 1];
    utfSum[0] <== 0;
    signal utfIndex[msgBytes];
    for (var i = 0; i < msgBytes; i++) {
        utfSum[i+1] <== states[i+1][1] * (1 - utfSum[i]) + utfSum[i];
        utfIndex[i] <== (1 - utfSum[i]) * states[i+1][1];
    }

    // gets the index as a number
    var idx = 0;
    for (var i = 0; i < msgBytes; i++) {
        idx = idx + utfIndex[i]*i;
    }

    // Current idx is the index of the = for sequence ?=
    // Will output 0 if not found
    component notFound = IsZero();
    notFound.in <== idx;

    signal output index <== idx * (1 - notFound.out);
}

//component main = UTF8End(1024);
