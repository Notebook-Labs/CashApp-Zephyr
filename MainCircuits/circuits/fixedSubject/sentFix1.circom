// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

/** 
 * This template verifies a fixed section of html.
 * More information can be found in the documentation
 * All equality testing so 0 constraints - all just labelling
 */
template SentFix1Regex() {
    signal input in[4];
    var fixed[4] = [32, 116, 111, 32];
    // check input matches fixed
    for (var i = 0; i < 4; i++) {
        in[i] === fixed[i];
    }
}
    