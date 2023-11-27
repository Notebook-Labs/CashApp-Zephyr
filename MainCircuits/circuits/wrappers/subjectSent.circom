// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../dep/extract.circom";
include "../../dep/parseSubject.circom";
include "../dynamic/name.circom";
include "../dynamic/fixAmount.circom";
include "../fixedSubject/subjectFix0.circom";
include "../fixedSubject/subjectFix1.circom";
include "../fixedSubject/subjectFix2.circom";
include "../fixedSubject/sentFix0.circom";
include "../fixedSubject/sentFix1.circom";
include "../fixedSubject/sentFix2.circom";


template SubjectSent(msgBytes) {

    signal input in[msgBytes];
    signal input dateLen;
    signal input emailLen;
    signal input subjectAmountLen;
    signal input subjectNameLen;

    var fix0Len = 5;
    var fix1Len = 38;
    var fix2Len = 10;
    var sentFix0Len = 10;
    var sentFix1Len = 4;
    var sentFix2Len = 24;
    var maxName = 380;
    var dateMin = 25;
    var dateMax = 35;
    var emailMin = 80;
    var emailMax = 600;
    var amountMin = 1;
    var amountMax = 9;
    var nameMin = 2;
    var nameMax = 380;

    var subjectLen = 600;
    var subjectMaxLines = 12;


    var dateRange = dateMax - dateMin + 1;
    var emailRange = dateRange + emailMax - emailMin;

    var amountRange = amountMax - amountMin + 1;
    var nameRange = amountRange + nameMax - nameMin;


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


    component emailUncertainty = UncertaintyExtraction(emailRange, fix2Len + subjectLen, fix0Len + dateMin + fix1Len + emailMin, msgBytes);
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
        subjectFix2Regex.in[i] <== fix2Array[0 + i];
    }

    component subjectParser = ParseSubject(subjectLen, subjectMaxLines);

    signal parsed[subjectLen];
    for (var i = 0; i < subjectLen; i++) {
        subjectParser.in[i] <== emailUncertainty.out[fix2Len + i];
    }

    for (var i = 0; i < subjectLen; i++) {
        parsed[i] <== subjectParser.subject[i];
    }


    signal sentFix0Array[sentFix0Len];
    for (var i = 0; i < sentFix0Len; i++) {
        sentFix0Array[i] <== parsed[i];
    }


    component sentFix0Regex = SentFix0Regex();
    for (var i = 0; i < sentFix0Len; i++) {
        sentFix0Regex.in[i] <== sentFix0Array[0 + i];
    }


    signal output amount;
    component amountRegex = FixAmountRegex(amountRange + amountMin);
    for (var i = 0; i < amountRange + amountMin; i++) {
        amountRegex.in[i] <== parsed[sentFix0Len + i];
	}
    amountRegex.len <== subjectAmountLen;
    amount <== amountRegex.out;


    component amountUncertainty = UncertaintyExtraction(amountRange, sentFix1Len, sentFix0Len + amountMin, subjectLen);
    amountUncertainty.indicatorLen <== subjectAmountLen - amountMin;
    for (var i = 0; i < subjectLen; i++) {
        amountUncertainty.in[i] <== parsed[i];
    }
    signal sentFix1Array[sentFix1Len];
    for (var i = 0; i < sentFix1Len; i++) {
        sentFix1Array[i] <== amountUncertainty.out[i];
    }


    component sentFix1Regex = SentFix1Regex();
    for (var i = 0; i < sentFix1Len; i++) {
        sentFix1Regex.in[i] <== sentFix1Array[0 + i];
    }


    signal output name[maxName];
    component nameRegex = NameRegex(nameRange + nameMin, maxName);
    for (var i = 0; i < nameRange + nameMin; i++) {
        nameRegex.in[i] <== parsed[sentFix0Len + amountMin + sentFix1Len + i];
    }
    nameRegex.start <== subjectAmountLen - amountMin;
    nameRegex.len <== subjectNameLen;
    for (var i = 0; i < maxName; i++) {
        log(nameRegex.out[i]);
        name[i] <== nameRegex.out[i];
     }


    component nameUncertainty = UncertaintyExtraction(nameRange, sentFix2Len, sentFix0Len + amountMin + sentFix1Len + nameMin, subjectLen);
    nameUncertainty.indicatorLen <== subjectNameLen - nameMin + subjectAmountLen - amountMin;
    for (var i = 0; i < subjectLen; i++) {
        nameUncertainty.in[i] <== parsed[i];
    }
    signal sentFix2Array[sentFix2Len];
    for (var i = 0; i < sentFix2Len; i++) {
        sentFix2Array[i] <== nameUncertainty.out[i];
    }


    signal output note;
    component sentFix2Regex = SentFix2Regex();
    for (var i = 0; i < sentFix2Len; i++) {
        sentFix2Regex.in[i] <== sentFix2Array[0 + i];
    }
    note <== sentFix2Regex.out;
}
