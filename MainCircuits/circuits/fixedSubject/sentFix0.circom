// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

/** 
 * This template verifies a fixed section of html.
 * More information can be found in the documentation
 * All equality testing so 0 constraints - all just labelling
 */
template SentFix0Regex() {
    signal input in[10];
    var fixed[10] = [89, 111, 117, 32, 115, 101, 110, 116, 32, 36];
    // check input matches fixed
    for (var i = 0; i < 10; i++) {
        in[i] === fixed[i];
    }
}
    