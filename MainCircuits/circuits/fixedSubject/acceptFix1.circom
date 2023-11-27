// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

/** 
 * This template verifies a fixed section of html.
 * More information can be found in the documentation
 * All equality testing so 0 constraints - all just labelling
 */
template AcceptFix1Regex() {
    signal input in[20];
    var fixed[20] = [32, 106, 117, 115, 116, 32, 97, 99, 99, 101, 112, 116, 101, 100, 32, 116, 104, 101, 32, 36];
    // check input matches fixed
    for (var i = 0; i < 20; i++) {
        in[i] === fixed[i];
    }
}
    