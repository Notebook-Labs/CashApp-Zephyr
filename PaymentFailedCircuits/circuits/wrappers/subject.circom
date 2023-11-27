// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../dep/extract.circom";
include "../fixedSubject/subjectFix0.circom";
include "../fixedSubject/subjectFix1.circom";
include "../fixedSubject/subjectFix2.circom";


template Subject(msgBytes) {

    signal input in[msgBytes];
    signal input dateLen;
    signal input emailLen;

    var fix0Len = 5;
    var fix1Len = 38;
    var fix2Len = 39;
    var dateMin = 25;
    var dateMax = 35;
    var emailMin = 80;
    var emailMax = 600;




    var dateRange = dateMax - dateMin + 1;
    var emailRange = dateRange + emailMax - emailMin;


    component subjectFix0Regex = SubjectFix0Regex();
    for (var i = 0; i < fix0Len; i++) {
        subjectFix0Regex.in[i] <== in[0 + i];
    }


    component dateUncertainty = UncertaintyExtraction(dateRange, fix1Len, fix0Len + dateMin, msgBytes);
    dateUncertainty.indicatorLen <== dateLen - dateMin;
    for (var i = 0; i < msgBytes; i++) {
        dateUncertainty.in[i] <== in[i];
    }
    signal fix1Array[fix1Len];
    for (var i = 0; i < fix1Len; i++) {
        fix1Array[i] <== dateUncertainty.out[i];
    }


    component subjectFix1Regex = SubjectFix1Regex();
    for (var i = 0; i < fix1Len; i++) {
        subjectFix1Regex.in[i] <== fix1Array[0 + i];
    }


    component emailUncertainty = UncertaintyExtraction(emailRange, fix2Len, fix0Len + dateMin + fix1Len + emailMin, msgBytes);
    emailUncertainty.indicatorLen <== emailLen - emailMin + dateLen - dateMin;
    for (var i = 0; i < msgBytes; i++) {
        emailUncertainty.in[i] <== in[i];
    }
    signal fix2Array[fix2Len];
    for (var i = 0; i < fix2Len; i++) {
        fix2Array[i] <== emailUncertainty.out[i];
    }


    component subjectFix2Regex = SubjectFix2Regex();
    for (var i = 0; i < fix2Len; i++) {
        log(fix2Array[0 + i]);
        subjectFix2Regex.in[i] <== fix2Array[0 + i];
    }
}
