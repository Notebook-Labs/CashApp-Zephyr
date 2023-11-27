// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/gates.circom";

/** 
 * This template verifies a fixed section of html.
 * More information can be found in the documentation
 */
template SentFix2Regex() {
    signal input in[24];
    var fixed[24] = [32, 102, 111, 114, 32, 0, 0, 0, 0, 32, 0, 0, 0, 0, 32, 0, 0, 0, 0, 32, 0, 0, 0, 0];
    // check input matches fixed
    for (var i = 0; i < 24; i++) {
        (in[i] - fixed[i]) * fixed[i] === 0;
    }

    
    //
    // Check and extract the note
    //

    // check the nonce/message values are 0-9. The venmo message should be 4 blocks of 0-9 with a space in-between each block.
    var claimIndices[16] = [5, 6, 7, 8, 10, 11, 12, 13, 15, 16, 17, 18, 20, 21, 22, 23];
    component lt[2][16];
    for (var i = 0; i < 16; i++) {
        lt[0][i] = LessThan(8);
        lt[0][i].in[0] <== 47;
        lt[0][i].in[1] <==  in[claimIndices[i]];

        lt[1][i] = LessThan(8);
        lt[1][i].in[0] <==  in[claimIndices[i]];
        lt[1][i].in[1] <== 58;

        lt[0][i].out * lt[1][i].out === 1;
    }

    // output nonce as a single signal
    signal nonce[17];
    nonce[0] <== 0;
     for (var i = 1; i < 17; i++) {
        nonce[i] <== 10 * nonce[i - 1] + (in[claimIndices[i - 1]] - 48);
    }

    signal output out;
    out <== nonce[16];
    

    

}
    