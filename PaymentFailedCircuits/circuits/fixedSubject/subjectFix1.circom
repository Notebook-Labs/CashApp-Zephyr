// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

/** 
 * This template verifies a fixed section of html.
 * More information can be found in the documentation
 * All equality testing so 0 constraints - all just labelling
 */
template SubjectFix1Regex() {
    signal input in[38];
    var fixed[38] = [13, 10, 102, 114, 111, 109, 58, 67, 97, 115, 104, 32, 65, 112, 112, 32, 60, 99, 97, 115, 104, 64, 115, 113, 117, 97, 114, 101, 46, 99, 111, 109, 62, 13, 10, 116, 111, 58];
    // check input matches fixed
    for (var i = 0; i < 38; i++) {
        in[i] === fixed[i];
    }
}
    