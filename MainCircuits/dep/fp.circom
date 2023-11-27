// SPDX-License-Identifier: GPL-3.0-only
// This file is derived from doubleblind-xyz/circom-rsa.
// Original work can be found at https://github.com/doubleblind-xyz/circom-rsa/blob/master/circuits/fp.circom.

pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/sign.circom";
include "./bigint.circom";
include "./bigintFunc.circom";

/**
 * These functions operate over values in Z/Zp for some integer p (typically,
 * but not necessarily prime). Values are stored as standard bignums with k
 * chunks of n bits, but intermediate values often have "overflow" bits inside
 * various chunks.
 *
 * These Fp functions will always correctly generate witnesses mod p, but they
 * do not *check* that values are normalized to < p; they only check that
 * values are correct mod p. This is to save the comparison circuit.
 * They *will* always check for intended results mod p (soundness), but it may
 * not have a unique intermediate signal.
 *
 * Conversely, some templates may not be satisfiable if the input witnesses are
 * not < p. This does not break completeness, as honest provers will always
 * generate witnesses which are canonical (between 0 and p). *
 * a * b = r mod p
 * a * b - p * q - r for some q
 *
 * n = 121, k = 9
 * 
 * We calculate in the follow way
 * Our inputs are expressed in k groups of n bits
 * We can think of these as the coefficients of a polynomial
 * When we evaluate the polynomial in 2^n we get back our original value
 * To calculate ab, we first interpolate the polynomial ab by evaluating a and b at different points
 * We then interpolate a polynomial pq + r in a similar way
 * We then get the polynomial ab - pq - r
 * We then check that this polynomial evaluates to 0 at 2^n
 *
 * We need to ensure that a, b < p otherwise the function may revert due to the carry check
 * credits to double-blind for this function
 */
template FpMul(n, k) {

    // ensure we always stay smaller than the field prime
    // 2n + logCeil(k) for AB and PQ
    // 2n + logCeil(k) + 1 for AB - PQ
    // 2n + logCeil(k) + 2 for AB - PQ - R
    assert(n + n + logCeil(k) + 2 <= 252);
    signal input a[k];
    signal input b[k];
    signal input p[k];

    signal output out[k];

    // evaluate a and b at 2k-1
    signal vAB[2*k-1];
    for (var x = 0; x < 2*k-1; x++) {
        var vA = polyEval(k, a, x);
        var vB = polyEval(k, b, x);
        vAB[x] <== vA * vB;
    }

    // standard polynomial interpolation to get ab but the coefficients may be overflowing
    var ab[200] = polyInterp(2*k-1, vAB);
    
    // abProper has length 2k - 1 + ceil(m/n) and each coefficient in the right number of bits
    var abProper[100] = getProperRepresentation(n + n + logCeil(k), n, 2*k-1, ab);

    var longDivOut[2][100] = longDiv(n, k, k, abProper, p);

    // Since we're only computing a*b, we know that q < p will suffice, so we
    // know it fits into k chunks and can do size n range checks.
    signal q[k];
    component qRangeCheck[k];
    signal r[k];
    component rRangeCheck[k];

    // ensure that q and r are in the right format
    for (var i = 0; i < k; i++) {
        q[i] <-- longDivOut[0][i];
        qRangeCheck[i] = Num2Bits(n); // verify less than 2^n so that evaluation at x = 2^n is correct
        qRangeCheck[i].in <== q[i];

        r[i] <-- longDivOut[1][i];
        rRangeCheck[i] = Num2Bits(n);
        rRangeCheck[i].in <== r[i];
    }

    // evaluate pq + r at 2k-1 points
    signal vPQR[2*k-1];
    for (var x = 0; x < 2*k-1; x++) {
        var vP = polyEval(k, p, x);
        var vQ = polyEval(k, q, x);
        var vR = polyEval(k, r, x);
        vPQR[x] <== vP * vQ + vR;
    }

    // get the polynomial ab - pq - r
    signal vT[2*k-1];
    for (var x = 0; x < 2*k-1; x++) {
        vT[x] <== vAB[x] - vPQR[x];
    }

    // interpolate the polynomial ab - pq - r to get the coefficients
    var t[200] = polyInterp(2*k-1, vT);

    // evaluate the polynomial at 2^n and ensure it's 0
    component tCheck = CheckCarryToZero(n, n + n + logCeil(k) + 2, 2*k-1);
    for (var i = 0; i < 2*k-1; i++) {
        tCheck.in[i] <== t[i];
    }

    // output the remainder
    for (var i = 0; i < k; i++) {
        out[i] <== r[i];
    }
}
