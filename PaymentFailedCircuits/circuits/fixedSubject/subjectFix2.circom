// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

/** 
 * This template verifies a fixed section of html.
 * More information can be found in the documentation
 * All equality testing so 0 constraints - all just labelling
 */
template SubjectFix2Regex() {
    signal input in[39];
    var fixed[39] = [13, 10, 115, 117, 98, 106, 101, 99, 116, 58, 80, 97, 121, 109, 101, 110, 116, 32, 102, 97, 105, 108, 101, 100, 13, 10, 109, 105, 109, 101, 45, 118, 101, 114, 115, 105, 111, 110, 58];
    // check input matches fixed
    for (var i = 0; i < 39; i++) {
        in[i] === fixed[i];
    }
}
    