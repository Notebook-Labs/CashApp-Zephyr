// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

/** 
 * This template verifies a fixed section of html.
 * More information can be found in the documentation
 * All equality testing so 0 constraints - all just labelling
 */
template PaidFix0Regex() {
    signal input in[9];
    var fixed[9] = [89, 111, 117, 32, 112, 97, 105, 100, 32];
    // check input matches fixed
    for (var i = 0; i < 9; i++) {
        in[i] === fixed[i];
    }
}
    