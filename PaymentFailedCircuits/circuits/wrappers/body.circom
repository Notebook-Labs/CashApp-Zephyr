// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../dep/extract.circom";
include "../fixedBody/fix1.circom";
include "../fixedBody/fix2.circom";
include "../fixedBody/fix3.circom";
include "../fixedBody/fix4.circom";


template Body(msgBytes) {

    signal input in[msgBytes];
    signal input partLen;
    signal input paymentLen;
    signal input coreLen;
    signal input postLen;

    signal input encodedLen;

    var fix1Len = 1111;
    var fix2Len = 1829;
    var fix3Len = 2831;
    var fix4Len = 1673;

    var fix1LenVar = 25;
    var fix2LenVar = 139;
    var fix3LenVar = 175;
    var fix4LenVar = 72;

    var partMin = 220;
    var partMax = 1420;
    var paymentMin = 10;
    var paymentMax = 785;
    var coreMin = 0;
    var coreMax = 5000;
    var postMin = 0;
    var postMax = 9000;




    var partRange = partMax - partMin + 1;
    var paymentRange = fix1LenVar + partRange + paymentMax - paymentMin;
    var coreRange = fix2LenVar + paymentRange + coreMax - coreMin;
    var postRange = fix3LenVar + coreRange + postMax - postMin;


    component partUncertainty = UncertaintyExtraction(partRange, fix1Len + fix1LenVar, partMin, msgBytes);
    partUncertainty.indicatorLen <== partLen - partMin;
    for (var i = 0; i < msgBytes; i++) {
        partUncertainty.in[i] <== in[i];
    }
    signal fix1Array[fix1Len + fix1LenVar];
    for (var i = 0; i < fix1Len + fix1LenVar; i++) {
        fix1Array[i] <== partUncertainty.out[i];
    }


    component fix1Regex = Fix1Regex();
    fix1Regex.encoded <== encodedLen;
    for (var i = 0; i < fix1Len + fix1LenVar; i++) {
        fix1Regex.in[i] <== fix1Array[0 + i];
    }


    component paymentUncertainty = UncertaintyExtraction(paymentRange, fix2Len + fix2LenVar, partMin + fix1Len + paymentMin, msgBytes);
    paymentUncertainty.indicatorLen <== paymentLen - paymentMin + partLen - partMin + encodedLen * (fix1LenVar);
    for (var i = 0; i < msgBytes; i++) {
        paymentUncertainty.in[i] <== in[i];
    }
    signal fix2Array[fix2Len + fix2LenVar];
    for (var i = 0; i < fix2Len + fix2LenVar; i++) {
        fix2Array[i] <== paymentUncertainty.out[i];
    }


    component fix2Regex = Fix2Regex();
    fix2Regex.encoded <== encodedLen;
    for (var i = 0; i < fix2Len + fix2LenVar; i++) {
        fix2Regex.in[i] <== fix2Array[0 + i];
    }


    component coreUncertainty = UncertaintyExtraction(coreRange, fix3Len + fix3LenVar, partMin + fix1Len + paymentMin + fix2Len + coreMin, msgBytes);
    coreUncertainty.indicatorLen <== coreLen - coreMin + paymentLen - paymentMin + partLen - partMin + encodedLen * (fix1LenVar + fix2LenVar);
    for (var i = 0; i < msgBytes; i++) {
        coreUncertainty.in[i] <== in[i];
    }
    signal fix3Array[fix3Len + fix3LenVar];
    for (var i = 0; i < fix3Len + fix3LenVar; i++) {
        fix3Array[i] <== coreUncertainty.out[i];
    }


    component fix3Regex = Fix3Regex();
    fix3Regex.encoded <== encodedLen;
    for (var i = 0; i < fix3Len + fix3LenVar; i++) {
        fix3Regex.in[i] <== fix3Array[0 + i];
    }


    component postUncertainty = UncertaintyExtraction(postRange, fix4Len + fix4LenVar, partMin + fix1Len + paymentMin + fix2Len + coreMin + fix3Len + postMin, msgBytes);
    postUncertainty.indicatorLen <== postLen - postMin + coreLen - coreMin + paymentLen - paymentMin + partLen - partMin + encodedLen * (fix1LenVar + fix2LenVar + fix3LenVar);
    for (var i = 0; i < msgBytes; i++) {
        postUncertainty.in[i] <== in[i];
    }
    signal fix4Array[fix4Len + fix4LenVar];
    for (var i = 0; i < fix4Len + fix4LenVar; i++) {
        fix4Array[i] <== postUncertainty.out[i];
    }


    signal output identifier;
    component fix4Regex = Fix4Regex();
    fix4Regex.encoded <== encodedLen;
    for (var i = 0; i < fix4Len + fix4LenVar; i++) {
        fix4Regex.in[i] <== fix4Array[0 + i];
    }
    identifier <== fix4Regex.out;
}
