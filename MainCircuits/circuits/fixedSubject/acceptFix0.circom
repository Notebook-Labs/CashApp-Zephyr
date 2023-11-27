// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

/** 
 * This template verifies a fixed section of html.
 * More information can be found in the documentation
 * All equality testing so 0 constraints - all just labelling
 */
template AcceptFix0Regex() {
    signal input in[10];
    var fixed[10] = [13, 10, 115, 117, 98, 106, 101, 99, 116, 58];
    // check input matches fixed
    for (var i = 0; i < 10; i++) {
        in[i] === fixed[i];
    }
}
    