// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../dep/extract.circom";
include "../../dep/parseSubject.circom";
include "../dynamic/fixName.circom";
include "../dynamic/amount.circom";
include "../fixedSubject/subjectFix0.circom";
include "../fixedSubject/subjectFix1.circom";
include "../fixedSubject/subjectFix2.circom";
include "../fixedSubject/acceptFix1.circom";
include "../fixedSubject/acceptFix2.circom";


template SubjectAccept(msgBytes) {

    signal input in[msgBytes];
    signal input dateLen;
    signal input emailLen;
    signal input subjectNameLen;
    signal input subjectAmountLen;

    var fix0Len = 5;
    var fix1Len = 38;
    var fix2Len = 10;
    var acceptFix1Len = 20;
    var acceptFix2Len = 33;
    var maxName = 380;
    var dateMin = 25;
    var dateMax = 35;
    var emailMin = 80;
    var emailMax = 600;
    var nameMin = 2;
    var nameMax = 380;
    var amountMin = 1;
    var amountMax = 9;

    var subjectLen = 600; 
    var subjectMaxLines = 12;




    var dateRange = dateMax - dateMin + 1;
    var emailRange = dateRange + emailMax - emailMin;


    var nameRange = nameMax - nameMin + 1;
    var amountRange = nameRange + amountMax - amountMin;

    //fix0 is 'date:'
    component subjectFix0Regex = SubjectFix0Regex();
    for (var i = 0; i < fix0Len; i++) {
        subjectFix0Regex.in[i] <== in[0 + i];
    }

    component dateUncertainty = UncertaintyExtraction(dateRange, fix1Len, fix0Len + dateMin, msgBytes);
    dateUncertainty.indicatorLen <== dateLen - dateMin;
    for (var i = 0; i < msgBytes; i++) {
        dateUncertainty.in[i] <== in[i];
    }

    //fix1 is \r\nfrom:Cash App <cash@square.com>\r\nto:
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

    //\r\nsubject:
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


    signal output name[maxName];
    component nameRegex = FixNameRegex(maxName);
    for (var i = 0; i < maxName; i++) {
        nameRegex.in[i] <== parsed[0 + i];
    }
    nameRegex.len <== subjectNameLen;
    for (var i = 0; i < maxName; i++) {
        name[i] <== nameRegex.out[i];
    }


    component nameUncertainty = UncertaintyExtraction(nameRange, acceptFix1Len, nameMin, subjectLen);
    nameUncertainty.indicatorLen <== subjectNameLen - nameMin;
    for (var i = 0; i < subjectLen; i++) {
        nameUncertainty.in[i] <== parsed[i];
    }

    //' just accepted the $'
    signal acceptFix1Array[acceptFix1Len];
    for (var i = 0; i < acceptFix1Len; i++) {
        acceptFix1Array[i] <== nameUncertainty.out[i];
    }

    component acceptFix1Regex = AcceptFix1Regex();
    for (var i = 0; i < acceptFix1Len; i++) {
        acceptFix1Regex.in[i] <== acceptFix1Array[0 + i];
    }


    signal output amount;
    component amountRegex = AmountRegex(amountRange + amountMin);
    for (var i = 0; i < amountRange + amountMin; i++) {
        amountRegex.in[i] <== parsed[nameMin + acceptFix1Len + i];
	}
    amountRegex.start <== subjectNameLen - nameMin;
    amountRegex.len <== subjectAmountLen;
    amount <== amountRegex.out;


    component amountUncertainty = UncertaintyExtraction(amountRange, acceptFix2Len, nameMin + acceptFix1Len + amountMin, subjectLen);
    amountUncertainty.indicatorLen <== subjectAmountLen - amountMin + subjectNameLen - nameMin;
    for (var i = 0; i < subjectLen; i++) {
        amountUncertainty.in[i] <== parsed[i];
    }

    //you sent for XXXX XXXX XXXX XXXX
    signal acceptFix2Array[acceptFix2Len];
    for (var i = 0; i < acceptFix2Len; i++) {
        acceptFix2Array[i] <== amountUncertainty.out[i];
    }


    signal output note;
    component acceptFix2Regex = AcceptFix2Regex();
    for (var i = 0; i < acceptFix2Len; i++) {
        acceptFix2Regex.in[i] <== acceptFix2Array[0 + i];
    }
    note <== acceptFix2Regex.out;
}
