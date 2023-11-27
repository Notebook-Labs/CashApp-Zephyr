// SPDX-License-Identifier: GPL-3.0-only
// This file is derived from 0xPARC circom-ecdsa under the GNU General Public License.
// Original work can be found at https://github.com/0xPARC/circom-ecdsa/blob/master/circuits/bigint_func.circom.

pragma circom 2.0.2;

/** 
 * Computes m/n and takes the ceiling 
 * Note that this function is only meant to be used for positive integers
 * Therefore both inputs should be checked to be less than 252 bits.
 * The input n must also be checked to not be 0
 */
function divCeil(m, n) {
    var ret;
    if (m % n == 0) {
        ret = m \ n;
    } else {
        ret = m \ n + 1;
    }
    return ret;
}

/**
 * A function to perform a normal log calculation takes the ceiling
 */
function logCeil(n) {
    
    if (n == 0) {
        return 0;
    }
    var nTemp = n-1;
    for (var i = 0; i < 254; i++) {
        if (nTemp == 0) {
            return i;
        }
        nTemp = nTemp \ 2;
    }
    return 254;
}

/**
 * High level idea is that this function takes an array in[k] where in[k] has a m 
 * bit field element in each register. For each element in in[k], this function 
 * takes the m - n leading bits and then adds them to the least significant bits of 
 * the next register. This is equivalent to evaluating in[k] as a polynomial where
 * x = 2^n and then shifting the registers so that each register is a coefficient
 * with size at most 2^n.
 * outputs an array of size k + ceilMN
 */
function getProperRepresentation(m, n, k, in) {
    // this call is safe as m < 253 bits and n is greater than 0
    var ceilMN = divCeil(m, n);

    var out[100]; // should be out[k + ceilMN]
    assert(k + ceilMN < 100);
    for (var i = 0; i < k; i++) {
        out[i] = in[i];
    }
    for (var i = k; i < 100; i++) {
        out[i] = 0;
    }
    
    
    assert(n <= m);
    for (var i = 0; i + 1 < k + ceilMN; i++) {
        //this code block first verifies that out[i] is between 2^m and -2^m. It
        //then adds 2^m to out[i] to get shiftedVal. It then shifts shiftedVal by 2^n
        //and stores the remainder in out[i] and adds the quotient to out[i+1]
        assert((1 << m) >= out[i] && out[i] >= -(1 << m));
        var shiftedVal = out[i] + (1 << m); // adding 2^m
        assert(0 <= shiftedVal && shiftedVal <= (1 << (m+1)));
        out[i] = shiftedVal & ((1 << n) - 1); // remainder of division by 2^n
        out[i+1] += (shiftedVal >> n) - (1 << (m - n));
    }

    return out;
}

/** 
 * A function to evaluate polynomial a at point x
 */
function polyEval(len, a, x) {
    var v = 0;
    for (var i = 0; i < len; i++) {
        // calculate term a_ix^i
        v += a[i] * (x ** i);
    }
    return v;
}

/**
 * A function to interpolate a degree len-1 polynomial given its evaluations at 0..len-1
 * we have out = P(x) = Sum_{i = 1}^{len + 1} v[i] * [(x-1)(x-2)..(x-i+1)(x-i-1)...(x-len-1)] / [(i-1)(i-2)..(i-i+1)(i-i-1)...(i-len-1)]
 * = Sum_{i = 1}^{len + 1} (v[i] / Prod_{i != j} (i - j)) * (x-1)(x-2)..(x-i+1)(x-i-1)...(x-len-1)
 */
function polyInterp(len, v) {
    assert(len <= 200);
    var out[200];
    for (var i = 0; i < len; i++) {
        out[i] = 0;
    }

    // Product_{i=0..len-1} (x-i)
    // This caluclates the coefficients we can see it as each iteration multiplies coefficients by (x-i)
    // fullPoly[i] contains the i-th coefficient of Product_{i=0..len-1} (x-i)
    var fullPoly[201];
    fullPoly[0] = 1;
    // we can think of each iteration as how the coefficients change when we multiply by (x - i)
    for (var i = 0; i < len; i++) {
        fullPoly[i+1] = 0;
        for (var j = i; j >= 0; j--) {
            fullPoly[j+1] += fullPoly[j];
            fullPoly[j] *= -i;
        }
    }

    for (var i = 0; i < len; i++) {

        // curV = Prod_{i != j} (i - j)
        var curV = 1;
        for (var j = 0; j < len; j++) {
            if (i == j) {
                // do nothing
            } else {
                curV *= i-j; 
            }
        }
        // curV = v[i] / Prod_{i != j} (i - j) 
        curV = v[i] / curV; 

        // We have the coefficients of Prod_{i = 0..len-1} (x-i) 
        // We are polynomial long division to get the coefficients of Prod_{i = 0..len-1} (x-i) / (x-k) 
        // And multiplying the coefficients by curV to calculate one of the terms in the sum for P(x)
        var curRem = fullPoly[len];
        for (var j = len-1; j >= 0; j--) {
            out[j] += curV * curRem; //curRem is the j-th coefficient of [Prod_{i = 0..len-1} (x-i)] /(x-i)
            curRem = fullPoly[j] + i * curRem;
        }

        // check a sanity check that (x-k) | Product_{i=0..len-1} (x-i)
        assert(curRem == 0);
    }

    return out;
}

/**
 * A function that checks if a bigint(a) > bigint(b) where each bigint has k chunks
 * 1 if true, 0 if false
 */
function longGt(k, a, b) {
    for (var i = k - 1; i >= 0; i--) {
        if (a[i] > b[i]) {
            return 1;
        }
        if (a[i] < b[i]) {
            return 0;
        }
    }
    return 0;
}

/**
 * A helper function to subtract two bigints
 * n bits per register
 * a has k registers
 * b has k registers
 * a >= b
 */
function longSub(n, k, a, b) {
    var diff[100];
    var borrow[100];
    for (var i = 0; i < k; i++) {
        if (i == 0) {
           if (a[i] >= b[i]) {
               diff[i] = a[i] - b[i];
               borrow[i] = 0;
            } else {
               diff[i] = a[i] - b[i] + (1 << n);
               borrow[i] = 1;
            }
        } else {
            if (a[i] >= b[i] + borrow[i - 1]) {
               diff[i] = a[i] - b[i] - borrow[i - 1];
               borrow[i] = 0;
            } else {
               diff[i] = (1 << n) + a[i] - b[i] - borrow[i - 1];
               borrow[i] = 1;
            }
        }
    }
    return diff;
}

/**
 * A helper function for scalar multiplication
 * a is a n-bit scalar
 * b has k registers
 */
function longScalarMult(n, k, a, b) {
    var out[100];
    for (var i = 0; i < 100; i++) {
        out[i] = 0;
    }
    for (var i = 0; i < k; i++) {
        var temp = out[i] + (a * b[i]);
        out[i] = temp % (1 << n);
        out[i + 1] = out[i + 1] + temp \ (1 << n);
    }
    return out;
}

/**
 * A function to perform lng division of two bigints
 * n bits per register
 * a has k + m registers
 * b has k registers
 * out[0] has length m + 1 -- quotient
 * out[1] has length k -- remainder
 * this implements algorithm of https://people.eecs.berkeley.edu/~fateman/282/F%20Wright%20notes/week4.pdf
 * We explain this further in our docs
 */
function longDiv(n, k, m, a, b){
    // out[0] is the quotient, out[1] is the remainder
    var out[2][100];

    // We are adjusting to make sure b has k registers with the most significant one non zero
    // The operations on m are because a has m + kOld registers
    // So we set mNew = mOld + kOld - kNew such that mNew + kNew = mOld + kOld
    m += k;
    while (b[k-1] == 0) {
        out[1][k] = 0;
        k--;
        assert(k > 0);
    }
    m -= k;

    // copy a into the remainder
    var remainder[200];
    for (var i = 0; i < m + k; i++) {
        remainder[i] = a[i];
    }

    var mult[200];
    var dividend[200];
    for (var i = m; i >= 0; i--) {
        // consider the first k non-zero bits of the remainder for each iteration, which
        // will be the bits between indices i and k + i - 1. 
        if (i == m) {
            dividend[k] = 0;
            for (var j = k - 1; j >= 0; j--) {
                dividend[j] = remainder[j + m];
            }
        } else {
            for (var j = k; j >= 0; j--) {
                dividend[j] = remainder[j + i];
            }
        }

        // compute the quotient for this iteration and put it directly in the output
        // out will be 
        out[0][i] = shortDiv(n, k, dividend, b);

        var multShift[100] = longScalarMult(n, k, out[0][i], b);
        var subtrahend[200];
        for (var j = 0; j < m + k; j++) {
            subtrahend[j] = 0;
        }

        for (var j = 0; j <= k; j++) {
            if (i + j < m + k) {
               subtrahend[i + j] = multShift[j];
            }
        }
        remainder = longSub(n, m + k, remainder, subtrahend);
    }
    for (var i = 0; i < k; i++) {
        out[1][i] = remainder[i];
    }
    out[1][k] = 0;

    return out;
}

/**
 * A helper function which does short division
 * n bits per register
 * a has k + 1 registers that are set
 * b has k registers
 * assumes leading digit of b is at least 2 ** (n - 1) 
 * 0 <= a < (2**n) * b
 */
function shortDivNorm(n, k, a, b) {
   // calculates the qhat as in the paper
   var qhat = (a[k] * (1 << n) + a[k - 1]) \ b[k - 1]; // quotient of integer division
   // in the case of polynomial long division, this case won't get hit as  0 <= a < (2**n) * b
   if (qhat > (1 << n) - 1) {
      qhat = (1 << n) - 1;
   }

   // per the paper we have qhat -2 <= ret <= qhat

   var mult[100] = longScalarMult(n, k, qhat, b);
   // if !(qhat \cdot b > a), then qhat is the correct coefficient because we have ret <= qhat from the 
   // paper and that ret is the largest value such that ret \cdot b <= a

   if (longGt(k + 1, mult, a) == 1) {
      mult = longSub(n, k + 1, mult, b);
      // do a similar check to before - if (qhat-1) * b > a -> leaves only qhat-2 as an option.
      if (longGt(k + 1, mult, a) == 1) {
         return qhat - 2;
      } else {
         return qhat - 1;
      }
   } else {
       return qhat;
   }
}

/**
 * A helper function to normalize the inputs of the short division function
 * n bits per register
 * a has k + 1 registers
 * b has k registers
 * assumes leading digit of b is non-zero
 * 0 <= a < (2**n) * b
 */
function shortDiv(n, k, a, b) {
   // We multiply a and b by scale so that the leading digit of b is at least 2 ** (n - 1)
   var scale = (1 << n) \ (1 + b[k - 1]); // quotient of integer division

   // k + 1 registers now because a <= (2^n - 1) * b
   var normA[100] = longScalarMult(n, k + 1, scale, a);
   // k registers now
   var normB[100] = longScalarMult(n, k, scale, b);

   var ret;

   // removed checking if b[k] != 0 from the 0xPARC implementation but this case won't be hit per our proof in the github
   ret = shortDivNorm(n, k, normA, normB);

   // returning quotient so no post-processing is required
   return ret;
}


