// SPDX-License-Identifier: GPL-3.0-only
// This file is derived from 0xPARC circom-ecdsa under the GNU General Public License.
// Original work can be found at https://github.com/0xPARC/circom-ecdsa/blob/master/circuits/bigint.circom.

pragma circom 2.0.2;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/gates.circom";
include "bigintFunc.circom";

// credits to 0xPARC for this file

/*
 * A template to check that one bigint is larger than another
 * a, b are bigints where a[0], b[0] are the LSB,
 * We know that a > b is there exists i such that a[i] > b[i] and a[j] = b[j] for all j > i
 * We check if this property holds for some i
 */
template BigLessThan(n, k) {
    signal input a[k];
    signal input b[k];
    signal output out;

    component lt[k];
    component eq[k];

    // pre computes all the less than and equals gates

    // In practice we know that n < 122 therefore the LessThan template is safe since
    // we are guaranteed that a, b <= p/2
    for (var i = 0; i < k; i++) {
        // this is safe as a and b are range checked before calling it
        lt[i] = LessThan(n);
        lt[i].in[0] <== a[i];
        lt[i].in[1] <== b[i];
        eq[i] = IsEqual();
        eq[i].in[0] <== a[i];
        eq[i].in[1] <== b[i];
    }

    // ors[i] holds (lt[k - 1] || (eq[k - 1] && lt[k - 2]) .. || (eq[k - 1] && .. && lt[i]))
    // ands[i] holds (eq[k - 1] && .. && lt[i])
    // eqAnds[i] holds (eq[k - 1] && .. && eq[i])
    component ors[k - 1];
    component ands[k - 1];
    component eqAnds[k - 1];
    for (var i = k - 2; i >= 0; i--) {
        ands[i] = AND();
        eqAnds[i] = AND();
        ors[i] = OR();

        if (i == k - 2) {
           ands[i].a <== eq[k - 1].out;
           ands[i].b <== lt[k - 2].out;
           eqAnds[i].a <== eq[k - 1].out;
           eqAnds[i].b <== eq[k - 2].out;
           ors[i].a <== lt[k - 1].out;
           ors[i].b <== ands[i].out;
        } else {
           ands[i].a <== eqAnds[i + 1].out;
           ands[i].b <== lt[i].out;
           eqAnds[i].a <== eqAnds[i + 1].out;
           eqAnds[i].b <== eq[i].out;
           ors[i].a <== ors[i + 1].out;
           ors[i].b <== ands[i].out;
        }
     }
     out <== ors[0].out;
}

/**
 * This template checks that a polynomial (whose coefficients are in a certain format) evaluates to 0 in 2^n
 * in[i] contains values in the range -2^(m-1) to 2^(m-1)
 * constrains that in[] as a big integer is zero
 * This function evaluates a polynomial of degree k-1 at 2^n and checks that it is zero
 * checks that for a polynomial P(x) = Sum_( p_jX^j ), P(2^n) = 0
 * We do this because we represent our numbers as chunks of n bit binary a_0, ... a_{k-1} therefore a = Sum_{ a_i (2^n)^i}
 * Therefore when we multiply or add polynomials whose coefficients are a_i or b_i where both numbers are split in n chuck binary
 * To get the value of AB we need to convert it back to binary by evaluating in 2^n
 * As an example a = a_1 || a_0, a = b_1 || b_0, then ab = (a_1b_1 << 2n) + (a_1b_0 + a_0b_1 << n) + a_0b_0
 * Now if A(X) = a_1X + a_0, B(X) = b_1X + b_0, we can verify that ab = AB(2^n) 
 */
template CheckCarryToZero(n, m, k) {
    assert(k >= 2);
    
    var EPSILON = 3;
    
    // need to check that the range check at the bottom is sufficient to check that carry[i] * (1<<n) doesn't overflow
    // you need carry[i] * (1<<n) to not overflow, so we must have that carry[i] <= 2^(253 - n)
    assert(253 >= m + EPSILON); 

    signal input in[k];
    
    signal carry[k];
    component carryRangeChecks[k];
    for (var i = 0; i < k-1; i++){
        carryRangeChecks[i] = Num2Bits(m + EPSILON - n); 

        // this is ensuring that every coefficient is a multiple of 2^n and then adding the carry to the next term
        if( i == 0 ) {
            // for the first index, need to check that it's a multiple of 2^n 
            carry[i] <-- in[i] / (1<<n);
            in[i] === carry[i] * (1<<n);
        } else {
            carry[i] <-- (in[i] + carry[i-1]) / (1<<n);
            in[i] + carry[i-1] === carry[i] * (1<<n);
        }
        // checking carry is in the range of - 2^(m-n-1+eps), 2^(m+-n-1+eps)
        // checking that carry has less than m + EPSILON - n bits which for us is n + logCeil(k) + 4 
        // we need to add to ensure there is no two's complement binary padding hence the addition to make it positive
        

        // this is safe as carry[i] has at most m + EPSILON - n bits when n >> k which hold in our case
        // carry[i] is written in two's complement so the addition is required to make it positive
        carryRangeChecks[i].in <== carry[i] + ( 1<< (m + EPSILON - n - 1));
    }

    // now that all carries have been passed forward this is checking that P(2^n) = 0
    in[k-1] + carry[k-2] === 0;   
}
