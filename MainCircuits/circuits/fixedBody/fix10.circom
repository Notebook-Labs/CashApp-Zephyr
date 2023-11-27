// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/gates.circom";

/** 
 * This template verifies a fixed section of html.
 * More information can be found in the documentation
 */
template Fix10Regex() {
    signal input in[1673 + 72];
    
    signal input encoded;

    var fixed0[1673 + 72] = [13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 47, 100, 105, 118, 62, 60, 47, 116, 100, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 47, 116, 114, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 116, 114, 32, 99, 108, 97, 115, 115, 61, 34, 100, 101, 116, 97, 105, 108, 45, 114, 111, 119, 34, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 116, 100, 32, 97, 108, 105, 103, 110, 61, 34, 108, 101, 102, 116, 34, 32, 99, 108, 97, 115, 115, 61, 34, 100, 101, 116, 97, 105, 108, 45, 114, 111, 119, 45, 116, 101, 120, 116, 34, 32, 115, 116, 121, 108, 101, 61, 34, 99, 111, 108, 111, 114, 58, 32, 35, 57, 57, 57, 59, 32, 32, 102, 111, 110, 116, 45, 102, 97, 109, 105, 108, 121, 58, 32, 45, 97, 112, 112, 108, 101, 45, 115, 121, 115, 116, 101, 109, 44, 32, 66, 108, 105, 110, 107, 77, 97, 99, 83, 121, 115, 116, 101, 109, 70, 111, 110, 116, 44, 32, 72, 101, 108, 118, 101, 116, 105, 99, 97, 32, 78, 101, 117, 101, 44, 32, 72, 101, 108, 118, 101, 116, 105, 99, 97, 44, 32, 65, 114, 105, 97, 108, 44, 32, 115, 97, 110, 115, 45, 115, 101, 114, 105, 102, 59, 32, 32, 102, 111, 110, 116, 45, 115, 105, 122, 101, 58, 32, 49, 52, 112, 120, 59, 32, 32, 108, 105, 110, 101, 45, 104, 101, 105, 103, 104, 116, 58, 32, 50, 52, 112, 120, 59, 32, 32, 102, 111, 110, 116, 45, 119, 101, 105, 103, 104, 116, 58, 32, 51, 48, 48, 59, 32, 32, 108, 101, 116, 116, 101, 114, 45, 115, 112, 97, 99, 105, 110, 103, 58, 32, 48, 46, 50, 112, 120, 59, 34, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 100, 105, 118, 32, 99, 108, 97, 115, 115, 61, 34, 108, 97, 98, 101, 108, 34, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 73, 100, 101, 110, 116, 105, 102, 105, 101, 114, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 47, 100, 105, 118, 62, 60, 47, 116, 100, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 116, 100, 32, 97, 108, 105, 103, 110, 61, 34, 114, 105, 103, 104, 116, 34, 32, 99, 108, 97, 115, 115, 61, 34, 100, 101, 116, 97, 105, 108, 45, 114, 111, 119, 45, 116, 101, 120, 116, 34, 32, 115, 116, 121, 108, 101, 61, 34, 99, 111, 108, 111, 114, 58, 32, 35, 57, 57, 57, 59, 32, 32, 102, 111, 110, 116, 45, 102, 97, 109, 105, 108, 121, 58, 32, 45, 97, 112, 112, 108, 101, 45, 115, 121, 115, 116, 101, 109, 44, 32, 66, 108, 105, 110, 107, 77, 97, 99, 83, 121, 115, 116, 101, 109, 70, 111, 110, 116, 44, 32, 72, 101, 108, 118, 101, 116, 105, 99, 97, 32, 78, 101, 117, 101, 44, 32, 72, 101, 108, 118, 101, 116, 105, 99, 97, 44, 32, 65, 114, 105, 97, 108, 44, 32, 115, 97, 110, 115, 45, 115, 101, 114, 105, 102, 59, 32, 32, 102, 111, 110, 116, 45, 115, 105, 122, 101, 58, 32, 49, 52, 112, 120, 59, 32, 32, 108, 105, 110, 101, 45, 104, 101, 105, 103, 104, 116, 58, 32, 50, 52, 112, 120, 59, 32, 32, 102, 111, 110, 116, 45, 119, 101, 105, 103, 104, 116, 58, 32, 51, 48, 48, 59, 32, 32, 108, 101, 116, 116, 101, 114, 45, 115, 112, 97, 99, 105, 110, 103, 58, 32, 48, 46, 50, 112, 120, 59, 34, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 100, 105, 118, 32, 99, 108, 97, 115, 115, 61, 34, 118, 97, 108, 117, 101, 34, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 35, 0, 0, 0, 0, 0, 0, 0, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 47, 100, 105, 118, 62, 60, 47, 116, 100, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 47, 116, 114, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 116, 114, 32, 99, 108, 97, 115, 115, 61, 34, 100, 101, 116, 97, 105, 108, 45, 114, 111, 119, 34, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 116, 100, 32, 97, 108, 105, 103, 110, 61, 34, 108, 101, 102, 116, 34, 32, 99, 108, 97, 115, 115, 61, 34, 100, 101, 116, 97, 105, 108, 45, 114, 111, 119, 45, 116, 101, 120, 116, 34, 32, 115, 116, 121, 108, 101, 61, 34, 99, 111, 108, 111, 114, 58, 32, 35, 57, 57, 57, 59, 32, 32, 102, 111, 110, 116, 45, 102, 97, 109, 105, 108, 121, 58, 32, 45, 97, 112, 112, 108, 101, 45, 115, 121, 115, 116, 101, 109, 44, 32, 66, 108, 105, 110, 107, 77, 97, 99, 83, 121, 115, 116, 101, 109, 70, 111, 110, 116, 44, 32, 72, 101, 108, 118, 101, 116, 105, 99, 97, 32, 78, 101, 117, 101, 44, 32, 72, 101, 108, 118, 101, 116, 105, 99, 97, 44, 32, 65, 114, 105, 97, 108, 44, 32, 115, 97, 110, 115, 45, 115, 101, 114, 105, 102, 59, 32, 32, 102, 111, 110, 116, 45, 115, 105, 122, 101, 58, 32, 49, 52, 112, 120, 59, 32, 32, 108, 105, 110, 101, 45, 104, 101, 105, 103, 104, 116, 58, 32, 50, 52, 112, 120, 59, 32, 32, 102, 111, 110, 116, 45, 119, 101, 105, 103, 104, 116, 58, 32, 51, 48, 48, 59, 32, 32, 108, 101, 116, 116, 101, 114, 45, 115, 112, 97, 99, 105, 110, 103, 58, 32, 48, 46, 50, 112, 120, 59, 34, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 100, 105, 118, 32, 99, 108, 97, 115, 115, 61, 34, 108, 97, 98, 101, 108, 34, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 84, 111, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 47, 100, 105, 118, 62, 60, 47, 116, 100, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 116, 100, 32, 97, 108, 105, 103, 110, 61, 34, 114, 105, 103, 104, 116, 34, 32, 99, 108, 97, 115, 115, 61, 34, 100, 101, 116, 97, 105, 108, 45, 114, 111, 119, 45, 116, 101, 120, 116, 34, 32, 115, 116, 121, 108, 101, 61, 34, 99, 111, 108, 111, 114, 58, 32, 35, 57, 57, 57, 59, 32, 32, 102, 111, 110, 116, 45, 102, 97, 109, 105, 108, 121, 58, 32, 45, 97, 112, 112, 108, 101, 45, 115, 121, 115, 116, 101, 109, 44, 32, 66, 108, 105, 110, 107, 77, 97, 99, 83, 121, 115, 116, 101, 109, 70, 111, 110, 116, 44, 32, 72, 101, 108, 118, 101, 116, 105, 99, 97, 32, 78, 101, 117, 101, 44, 32, 72, 101, 108, 118, 101, 116, 105, 99, 97, 44, 32, 65, 114, 105, 97, 108, 44, 32, 115, 97, 110, 115, 45, 115, 101, 114, 105, 102, 59, 32, 32, 102, 111, 110, 116, 45, 115, 105, 122, 101, 58, 32, 49, 52, 112, 120, 59, 32, 32, 108, 105, 110, 101, 45, 104, 101, 105, 103, 104, 116, 58, 32, 50, 52, 112, 120, 59, 32, 32, 102, 111, 110, 116, 45, 119, 101, 105, 103, 104, 116, 58, 32, 51, 48, 48, 59, 32, 32, 108, 101, 116, 116, 101, 114, 45, 115, 112, 97, 99, 105, 110, 103, 58, 32, 48, 46, 50, 112, 120, 59, 34, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 100, 105, 118, 32, 99, 108, 97, 115, 115, 61, 34, 118, 97, 108, 117, 101, 34, 62, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    
    var fixed1[1745] = [13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 47, 100, 105, 118, 62, 60, 47, 116, 100, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 47, 116, 114, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 116, 114, 32, 99, 108, 97, 115, 115, 61, 51, 68, 34, 100, 101, 116, 97, 105, 108, 45, 114, 111, 119, 34, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 116, 100, 32, 97, 108, 105, 103, 110, 61, 51, 68, 34, 108, 101, 102, 116, 34, 32, 99, 108, 97, 115, 115, 61, 51, 68, 34, 100, 101, 116, 97, 105, 108, 45, 114, 111, 119, 45, 116, 101, 120, 116, 34, 32, 115, 116, 121, 108, 101, 61, 13, 10, 61, 51, 68, 34, 99, 111, 108, 111, 114, 58, 32, 35, 57, 57, 57, 59, 32, 32, 102, 111, 110, 116, 45, 102, 97, 109, 105, 108, 121, 58, 32, 45, 97, 112, 112, 108, 101, 45, 115, 121, 115, 116, 101, 109, 44, 32, 66, 108, 105, 110, 107, 77, 97, 99, 83, 121, 115, 116, 101, 109, 70, 111, 110, 116, 44, 32, 72, 101, 108, 118, 101, 116, 105, 99, 97, 61, 13, 10, 32, 78, 101, 117, 101, 44, 32, 72, 101, 108, 118, 101, 116, 105, 99, 97, 44, 32, 65, 114, 105, 97, 108, 44, 32, 115, 97, 110, 115, 45, 115, 101, 114, 105, 102, 59, 32, 32, 102, 111, 110, 116, 45, 115, 105, 122, 101, 58, 32, 49, 52, 112, 120, 59, 32, 32, 108, 105, 110, 101, 45, 104, 101, 105, 103, 104, 116, 58, 32, 50, 52, 112, 120, 59, 32, 61, 13, 10, 32, 102, 111, 110, 116, 45, 119, 101, 105, 103, 104, 116, 58, 32, 51, 48, 48, 59, 32, 32, 108, 101, 116, 116, 101, 114, 45, 115, 112, 97, 99, 105, 110, 103, 58, 32, 48, 46, 50, 112, 120, 59, 34, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 100, 105, 118, 32, 99, 108, 97, 115, 115, 61, 51, 68, 34, 108, 97, 98, 101, 108, 34, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 73, 100, 101, 110, 116, 105, 102, 105, 101, 114, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 47, 100, 105, 118, 62, 60, 47, 116, 100, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 116, 100, 32, 97, 108, 105, 103, 110, 61, 51, 68, 34, 114, 105, 103, 104, 116, 34, 32, 99, 108, 97, 115, 115, 61, 51, 68, 34, 100, 101, 116, 97, 105, 108, 45, 114, 111, 119, 45, 116, 101, 120, 116, 34, 32, 115, 116, 121, 108, 61, 13, 10, 101, 61, 51, 68, 34, 99, 111, 108, 111, 114, 58, 32, 35, 57, 57, 57, 59, 32, 32, 102, 111, 110, 116, 45, 102, 97, 109, 105, 108, 121, 58, 32, 45, 97, 112, 112, 108, 101, 45, 115, 121, 115, 116, 101, 109, 44, 32, 66, 108, 105, 110, 107, 77, 97, 99, 83, 121, 115, 116, 101, 109, 70, 111, 110, 116, 44, 32, 72, 101, 108, 118, 101, 116, 105, 99, 61, 13, 10, 97, 32, 78, 101, 117, 101, 44, 32, 72, 101, 108, 118, 101, 116, 105, 99, 97, 44, 32, 65, 114, 105, 97, 108, 44, 32, 115, 97, 110, 115, 45, 115, 101, 114, 105, 102, 59, 32, 32, 102, 111, 110, 116, 45, 115, 105, 122, 101, 58, 32, 49, 52, 112, 120, 59, 32, 32, 108, 105, 110, 101, 45, 104, 101, 105, 103, 104, 116, 58, 32, 50, 52, 112, 120, 59, 61, 13, 10, 32, 32, 102, 111, 110, 116, 45, 119, 101, 105, 103, 104, 116, 58, 32, 51, 48, 48, 59, 32, 32, 108, 101, 116, 116, 101, 114, 45, 115, 112, 97, 99, 105, 110, 103, 58, 32, 48, 46, 50, 112, 120, 59, 34, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 100, 105, 118, 32, 99, 108, 97, 115, 115, 61, 51, 68, 34, 118, 97, 108, 117, 101, 34, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 35, 0, 0, 0, 0, 0, 0, 0, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 47, 100, 105, 118, 62, 60, 47, 116, 100, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 47, 116, 114, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 116, 114, 32, 99, 108, 97, 115, 115, 61, 51, 68, 34, 100, 101, 116, 97, 105, 108, 45, 114, 111, 119, 34, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 116, 100, 32, 97, 108, 105, 103, 110, 61, 51, 68, 34, 108, 101, 102, 116, 34, 32, 99, 108, 97, 115, 115, 61, 51, 68, 34, 100, 101, 116, 97, 105, 108, 45, 114, 111, 119, 45, 116, 101, 120, 116, 34, 32, 115, 116, 121, 108, 101, 61, 13, 10, 61, 51, 68, 34, 99, 111, 108, 111, 114, 58, 32, 35, 57, 57, 57, 59, 32, 32, 102, 111, 110, 116, 45, 102, 97, 109, 105, 108, 121, 58, 32, 45, 97, 112, 112, 108, 101, 45, 115, 121, 115, 116, 101, 109, 44, 32, 66, 108, 105, 110, 107, 77, 97, 99, 83, 121, 115, 116, 101, 109, 70, 111, 110, 116, 44, 32, 72, 101, 108, 118, 101, 116, 105, 99, 97, 61, 13, 10, 32, 78, 101, 117, 101, 44, 32, 72, 101, 108, 118, 101, 116, 105, 99, 97, 44, 32, 65, 114, 105, 97, 108, 44, 32, 115, 97, 110, 115, 45, 115, 101, 114, 105, 102, 59, 32, 32, 102, 111, 110, 116, 45, 115, 105, 122, 101, 58, 32, 49, 52, 112, 120, 59, 32, 32, 108, 105, 110, 101, 45, 104, 101, 105, 103, 104, 116, 58, 32, 50, 52, 112, 120, 59, 32, 61, 13, 10, 32, 102, 111, 110, 116, 45, 119, 101, 105, 103, 104, 116, 58, 32, 51, 48, 48, 59, 32, 32, 108, 101, 116, 116, 101, 114, 45, 115, 112, 97, 99, 105, 110, 103, 58, 32, 48, 46, 50, 112, 120, 59, 34, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 100, 105, 118, 32, 99, 108, 97, 115, 115, 61, 51, 68, 34, 108, 97, 98, 101, 108, 34, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 84, 111, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 47, 100, 105, 118, 62, 60, 47, 116, 100, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 116, 100, 32, 97, 108, 105, 103, 110, 61, 51, 68, 34, 114, 105, 103, 104, 116, 34, 32, 99, 108, 97, 115, 115, 61, 51, 68, 34, 100, 101, 116, 97, 105, 108, 45, 114, 111, 119, 45, 116, 101, 120, 116, 34, 32, 115, 116, 121, 108, 61, 13, 10, 101, 61, 51, 68, 34, 99, 111, 108, 111, 114, 58, 32, 35, 57, 57, 57, 59, 32, 32, 102, 111, 110, 116, 45, 102, 97, 109, 105, 108, 121, 58, 32, 45, 97, 112, 112, 108, 101, 45, 115, 121, 115, 116, 101, 109, 44, 32, 66, 108, 105, 110, 107, 77, 97, 99, 83, 121, 115, 116, 101, 109, 70, 111, 110, 116, 44, 32, 72, 101, 108, 118, 101, 116, 105, 99, 61, 13, 10, 97, 32, 78, 101, 117, 101, 44, 32, 72, 101, 108, 118, 101, 116, 105, 99, 97, 44, 32, 65, 114, 105, 97, 108, 44, 32, 115, 97, 110, 115, 45, 115, 101, 114, 105, 102, 59, 32, 32, 102, 111, 110, 116, 45, 115, 105, 122, 101, 58, 32, 49, 52, 112, 120, 59, 32, 32, 108, 105, 110, 101, 45, 104, 101, 105, 103, 104, 116, 58, 32, 50, 52, 112, 120, 59, 61, 13, 10, 32, 32, 102, 111, 110, 116, 45, 119, 101, 105, 103, 104, 116, 58, 32, 51, 48, 48, 59, 32, 32, 108, 101, 116, 116, 101, 114, 45, 115, 112, 97, 99, 105, 110, 103, 58, 32, 48, 46, 50, 112, 120, 59, 34, 62, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 100, 105, 118, 32, 99, 108, 97, 115, 115, 61, 51, 68, 34, 118, 97, 108, 117, 101, 34, 62];

    // check input matches fixed
    for (var i = 0; i < 1745; i++) {
        encoded * (fixed1[i] * (fixed1[i] - in[i]) + fixed0[i] * (fixed0[i] - in[i])) === fixed0[i] * (fixed0[i] - in[i]);
    }

    

    
    //
    // Check and extract the identifier
    //

    // check the identifier values are 0-9 A-Z
    var identifierIndices0[7] = [852, 853, 854, 855, 856, 857, 858];

    var identifierIndices1[7] = [888, 889, 890, 891, 892, 893, 894];

    signal values[7];

    for (var i = 0; i < 7; i++) {
        values[i] <== encoded * (in[identifierIndices1[i]] - in[identifierIndices0[i]]) + in[identifierIndices0[i]];
    }
    
    
    
    component lt[4][7];
    component and[2][7];
    signal numberSum[7];
    signal letterSum[7];
    for (var i = 0; i < 7; i++) {
        
        // check number
        lt[0][i] = LessThan(8);
        lt[0][i].in[0] <== 47;
        lt[0][i].in[1] <==  values[i];

        lt[1][i] = LessThan(8);
        lt[1][i].in[0] <==  values[i];
        lt[1][i].in[1] <== 58;

        and[0][i] = AND();
        and[0][i].a <== lt[0][i].out;
        and[0][i].b <== lt[1][i].out;

        numberSum[i] <== and[0][i].out * (values[i] - 48);

        // check letter
        lt[2][i] = LessThan(8);
        lt[2][i].in[0] <== 64;
        lt[2][i].in[1] <==  values[i];

        lt[3][i] = LessThan(8);
        lt[3][i].in[0] <==  values[i];
        lt[3][i].in[1] <== 91;

        and[1][i] = AND();
        and[1][i].a <== lt[2][i].out;
        and[1][i].b <== lt[3][i].out;

        letterSum[i] <== and[1][i].out * (values[i] - 55);

        and[0][i].out + and[1][i].out === 1;
    }

    // output nonce as a single signal
    signal nonce[7+1];
    nonce[0] <== 0;
     for (var i = 1; i <= 7; i++) {
        nonce[i] <== 36 * nonce[i - 1] + numberSum[i - 1] + letterSum[i - 1];
    }

    signal output out;
    out <== nonce[7];
    

}
    