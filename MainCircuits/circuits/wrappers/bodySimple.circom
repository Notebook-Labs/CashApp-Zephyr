// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../dep/extract.circom";
include "../../dep/cleanLines.circom";
include "../dynamic/fixName.circom";
include "../dynamic/amount.circom";
include "../dynamic/fixUsername.circom";
include "../fixedBody/fix1.circom";
include "../fixedBody/fix2.circom";
include "../fixedBody/fix3.circom";
include "../fixedBody/fix4.circom";
include "../fixedBody/fix5.circom";
include "../fixedBody/fix6.circom";
include "../fixedBody/fix7.circom";
include "../fixedBody/fix8.circom";
include "../fixedBody/fix9.circom";


template BodySimple(msgBytes) {

    signal input in[msgBytes];
    signal input partLen;
    signal input paymentLen;
    signal input photoLen;
    signal input nameLen;
    signal input usernameLen;
    signal input messageLen;
    signal input amountLen;
    signal input methodLen;
    signal input nameExtractLen;
    signal input firstAmountLen;
    signal input usernamePartLen;

    signal input encodedLen;

    var fix1Len = 1111;
    var fix2Len = 1829;
    var fix3Len = 746;
    var fix4Len = 669;
    var fix5Len = 651;
    var fix6Len = 2830;
    var fix7Len = 1935;
    var fix8Len = 460;
    var fix9Len = 387;
    var fix10Len = 1673;

    var fix1LenVar = 25;
    var fix2LenVar = 139;
    var fix3LenVar = 34;
    var fix4LenVar = 37;
    var fix5LenVar = 37;
    var fix6LenVar = 175;
    var fix7LenVar = 123;
    var fix8LenVar = 19;
    var fix9LenVar = 17;
    var fix10LenVar = 72;

    var maxName = 380;
    var maxUsername = 21;
    var partMin = 280;
    var partMax = 1300;
    var paymentMin = 10;
    var paymentMax = 785;
    var photoMin = 465;
    var photoMax = 609;
    var nameMin = 20;
    var nameMax = 610;
    var usernameMin = 1;
    var usernameMax = 21;
    var usernamePartMin = 1+7;
    var usernamePartMax = 21+10;
    var firstAmountMin = 1+12;
    var firstAmountMax = 9+15;
    var messageMin = 0;
    var messageMax = 1600;
    var amountMin = 1;
    var amountMax = 9;
    var methodMin = 1;
    var methodMax = 201;




    var partRange = partMax - partMin + 1;
    var paymentRange = fix1LenVar + partRange + paymentMax - paymentMin;
    var photoRange = fix2LenVar + paymentRange + photoMax - photoMin;
    var nameRange = fix3LenVar + photoRange + nameMax - nameMin;
    var usernameRange = fix4LenVar + nameRange + usernamePartMax - usernamePartMin;
    var firstAmountRange = fix5LenVar + usernameRange + firstAmountMax - firstAmountMin;
    var messageRange = fix6LenVar + firstAmountRange + messageMax - messageMin;
    var amountRange = fix7LenVar + messageRange + amountMax - amountMin;
    var methodRange = fix8LenVar + fix9LenVar + amountRange + methodMax - methodMin;


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
    paymentUncertainty.indicatorLen <== paymentLen - paymentMin + partLen - partMin + encodedLen * fix1LenVar;
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

    component photoUncertainty = UncertaintyExtraction(photoRange, fix3Len + fix3LenVar, partMin + fix1Len + paymentMin + fix2Len + photoMin, msgBytes);
    photoUncertainty.indicatorLen <== photoLen - photoMin + paymentLen - paymentMin + partLen - partMin + encodedLen * (fix1LenVar + fix2LenVar);
    for (var i = 0; i < msgBytes; i++) {
        photoUncertainty.in[i] <== in[i];
    }
    signal fix3Array[fix3Len + fix3LenVar];
    for (var i = 0; i < fix3Len + fix3LenVar; i++) {
        fix3Array[i] <== photoUncertainty.out[i];
    }


    component fix3Regex = Fix3Regex();
    fix3Regex.encoded <== encodedLen;
    for (var i = 0; i < fix3Len + fix3LenVar; i++) {
        fix3Regex.in[i] <== fix3Array[0 + i];
    }

    //the constant 400 is the maximum length of the name including /r/n at the end of lines 
    component nameRegexUncertainty = UncertaintyExtraction(nameRange, 400, partMin + fix1Len + paymentMin + fix2Len + photoMin + fix3Len, msgBytes);
    nameRegexUncertainty.indicatorLen <== photoLen - photoMin + paymentLen - paymentMin + partLen - partMin + encodedLen * (fix1LenVar + fix2LenVar + fix3LenVar);
    for (var i = 0; i < msgBytes; i++) {
        nameRegexUncertainty.in[i] <== in[i];
    }

    component nameClean = CleanLines(400, 5);
    for (var i = 0; i < 400; i++) {
        nameClean.in[i] <== nameRegexUncertainty.out[i]; 
    }

    signal output name[maxName];
    component nameRegex = FixNameRegex(maxName);
    for (var i = 0; i < maxName; i++) {
        nameRegex.in[i] <== nameClean.clean[i];
    }
    nameRegex.len <== nameExtractLen;
    for (var i = 0; i < maxName; i++) {
        name[i] <== nameRegex.out[i];
    }

    component nameUncertainty = UncertaintyExtraction(nameRange, fix4Len + fix4LenVar, partMin + fix1Len + paymentMin + fix2Len + photoMin + fix3Len + nameMin, msgBytes);
    nameUncertainty.indicatorLen <== nameLen - nameMin + photoLen - photoMin + paymentLen - paymentMin + partLen - partMin + encodedLen * (fix1LenVar + fix2LenVar + fix3LenVar);
    for (var i = 0; i < msgBytes; i++) {
        nameUncertainty.in[i] <== in[i];
    }
    signal fix4Array[fix4Len + fix4LenVar];
    for (var i = 0; i < fix4Len + fix4LenVar; i++) {
        fix4Array[i] <== nameUncertainty.out[i];
    }


    component fix4Regex = Fix4Regex();
    fix4Regex.encoded <== encodedLen;
    for (var i = 0; i < fix4Len + fix4LenVar; i++) {
        fix4Regex.in[i] <== fix4Array[0 + i];
    }

    component usernameRegexUncertainty = UncertaintyExtraction(usernameRange, 25, partMin + fix1Len + paymentMin + fix2Len + photoMin + fix3Len + nameMin + fix4Len, msgBytes);
    usernameRegexUncertainty.indicatorLen <== nameLen - nameMin + photoLen - photoMin + paymentLen - paymentMin + partLen - partMin + encodedLen * (fix1LenVar + fix2LenVar + fix3LenVar + fix4LenVar);
    for (var i = 0; i < msgBytes; i++) {
        usernameRegexUncertainty.in[i] <== in[i];
    }

    component usernameClean = CleanLines(25, 1);
    for (var i = 0; i < 25; i++) {
        usernameClean.in[i] <== usernameRegexUncertainty.out[i]; 
    }

    signal output username[maxUsername];
    component usernameRegex = FixUsernameRegex(maxUsername);
    for (var i = 0; i < maxUsername; i++) {
        usernameRegex.in[i] <== usernameClean.clean[i];
    }
    usernameRegex.len <== usernameLen;
    for (var i = 0; i < maxUsername; i++) {
        username[i] <== usernameRegex.out[i];
     }


    component usernameUncertainty = UncertaintyExtraction(usernameRange, fix5Len + fix5LenVar, partMin + fix1Len + paymentMin + fix2Len + photoMin + fix3Len + nameMin + fix4Len + usernamePartMin, msgBytes);
    usernameUncertainty.indicatorLen <== usernamePartLen - usernamePartMin + nameLen - nameMin + photoLen - photoMin + paymentLen - paymentMin + partLen - partMin + encodedLen * (fix1LenVar + fix2LenVar + fix3LenVar + fix4LenVar);
    for (var i = 0; i < msgBytes; i++) {
        usernameUncertainty.in[i] <== in[i];
    }
    signal fix5Array[fix5Len + fix5LenVar];
    for (var i = 0; i < fix5Len + fix5LenVar; i++) {
        fix5Array[i] <== usernameUncertainty.out[i];
    }


    component fix5Regex = Fix5Regex();
    fix5Regex.encoded <== encodedLen;
    for (var i = 0; i < fix5Len + fix5LenVar; i++) {
        fix5Regex.in[i] <== fix5Array[0 + i];
    }


    component firstAmountUncertainty = UncertaintyExtraction(firstAmountRange, fix6Len + fix6LenVar, partMin + fix1Len + paymentMin + fix2Len + photoMin + fix3Len + nameMin + fix4Len + usernamePartMin + fix5Len + firstAmountMin, msgBytes);
    firstAmountUncertainty.indicatorLen <== firstAmountLen - firstAmountMin + usernamePartLen - usernamePartMin + nameLen - nameMin + photoLen - photoMin + paymentLen - paymentMin + partLen - partMin + encodedLen * (fix1LenVar + fix2LenVar + fix3LenVar + fix4LenVar + fix5LenVar);
    for (var i = 0; i < msgBytes; i++) {
        firstAmountUncertainty.in[i] <== in[i];
    }
    signal fix6Array[fix6Len + fix6LenVar];
    for (var i = 0; i < fix6Len + fix6LenVar; i++) {
        fix6Array[i] <== firstAmountUncertainty.out[i];
    }


    signal output note;
    component fix6Regex = Fix6Regex();
    fix6Regex.encoded <== encodedLen;
    for (var i = 0; i < fix6Len + fix6LenVar; i++) {
        fix6Regex.in[i] <== fix6Array[0 + i];
    }
    note <== fix6Regex.out;


    component messageUncertainty = UncertaintyExtraction(messageRange, fix7Len + fix7LenVar, partMin + fix1Len + paymentMin + fix2Len + photoMin + fix3Len + nameMin + fix4Len + usernamePartMin + fix5Len + firstAmountMin + fix6Len + messageMin, msgBytes);
    messageUncertainty.indicatorLen <== messageLen - messageMin + firstAmountLen - firstAmountMin + usernamePartLen - usernamePartMin + nameLen - nameMin + photoLen - photoMin + paymentLen - paymentMin + partLen - partMin + encodedLen * (fix1LenVar + fix2LenVar + fix3LenVar + fix4LenVar + fix5LenVar + fix6LenVar);
    for (var i = 0; i < msgBytes; i++) {
        messageUncertainty.in[i] <== in[i];
    }
    signal fix7Array[fix7Len + fix7LenVar];
    for (var i = 0; i < fix7Len + fix7LenVar; i++) {
        fix7Array[i] <== messageUncertainty.out[i];
    }


    component fix7Regex = Fix7Regex();
    fix7Regex.encoded <== encodedLen;
    for (var i = 0; i < fix7Len + fix7LenVar; i++) {
        fix7Regex.in[i] <== fix7Array[0 + i];
    }


    signal output amount;
    component amountRegex = AmountRegex(amountRange + amountMin);
    for (var i = 0; i < amountRange + amountMin; i++) {
        amountRegex.in[i] <== in[partMin + fix1Len + paymentMin + fix2Len + photoMin + fix3Len + nameMin + fix4Len + usernamePartMin + fix5Len + firstAmountMin + fix6Len + messageMin + fix7Len + i];
	}
    amountRegex.start <== messageLen - messageMin + firstAmountLen - firstAmountMin + usernamePartLen - usernamePartMin + nameLen - nameMin + photoLen - photoMin + paymentLen - paymentMin + partLen - partMin + encodedLen * (fix1LenVar + fix2LenVar + fix3LenVar + fix4LenVar + fix5LenVar + fix6LenVar + fix7LenVar);
    amountRegex.len <== amountLen;
    amount <== amountRegex.out;


    component amountUncertainty = UncertaintyExtraction(amountRange, fix8Len + fix8LenVar, partMin + fix1Len + paymentMin + fix2Len + photoMin + fix3Len + nameMin + fix4Len + usernamePartMin + fix5Len + firstAmountMin + fix6Len + messageMin + fix7Len + amountMin, msgBytes);
    amountUncertainty.indicatorLen <== amountLen - amountMin + messageLen - messageMin + firstAmountLen - firstAmountMin + usernamePartLen - usernamePartMin + nameLen - nameMin + photoLen - photoMin + paymentLen - paymentMin + partLen - partMin + encodedLen * (fix1LenVar + fix2LenVar + fix3LenVar + fix4LenVar + fix5LenVar + fix6LenVar + fix7LenVar);
    for (var i = 0; i < msgBytes; i++) {
        amountUncertainty.in[i] <== in[i];
    }
    signal fix8Array[fix8Len + fix8LenVar];
    for (var i = 0; i < fix8Len + fix8LenVar; i++) {
        fix8Array[i] <== amountUncertainty.out[i];
    }


    component fix8Regex = Fix8Regex();
    fix8Regex.encoded <== encodedLen;
    for (var i = 0; i < fix8Len + fix8LenVar; i++) {
        fix8Regex.in[i] <== fix8Array[0 + i];
    }

    component fix9Uncertainty = UncertaintyExtraction(amountRange + fix8LenVar, fix9Len + fix9LenVar, partMin + fix1Len + paymentMin + fix2Len + photoMin + fix3Len + nameMin + fix4Len + usernamePartMin + fix5Len + firstAmountMin + fix6Len + messageMin + fix7Len + amountMin + fix8Len, msgBytes);
    fix9Uncertainty.indicatorLen <== amountLen - amountMin + messageLen - messageMin + firstAmountLen - firstAmountMin + usernamePartLen - usernamePartMin + nameLen - nameMin + photoLen - photoMin + paymentLen - paymentMin + partLen - partMin + encodedLen * (fix1LenVar + fix2LenVar + fix3LenVar + fix4LenVar + fix5LenVar + fix6LenVar + fix7LenVar + fix8LenVar);
    for (var i = 0; i < msgBytes; i++) {
        fix9Uncertainty.in[i] <== in[i];
    }
    signal fix9Array[fix9Len + fix9LenVar];
    for (var i = 0; i < fix9Len + fix9LenVar; i++) {
        fix9Array[i] <== fix9Uncertainty.out[i];
    }


    component fix9Regex = Fix9Regex();
    fix9Regex.encoded <== encodedLen;
    for (var i = 0; i < fix9Len + fix9LenVar; i++) {
        fix9Regex.in[i] <== fix9Array[i]; 
    }


    component methodUncertainty = UncertaintyExtraction(methodRange, fix10Len + fix10LenVar, partMin + fix1Len + paymentMin + fix2Len + photoMin + fix3Len + nameMin + fix4Len + usernamePartMin + fix5Len + firstAmountMin + fix6Len + messageMin + fix7Len + amountMin + fix8Len + fix9Len + methodMin, msgBytes);
    methodUncertainty.indicatorLen <== methodLen - methodMin + amountLen - amountMin + messageLen - messageMin + firstAmountLen - firstAmountMin + usernamePartLen - usernamePartMin + nameLen - nameMin + photoLen - photoMin + paymentLen - paymentMin + partLen - partMin + encodedLen * (fix1LenVar + fix2LenVar + fix3LenVar + fix4LenVar + fix5LenVar + fix6LenVar + fix7LenVar + fix8LenVar + fix9LenVar);
    for (var i = 0; i < msgBytes; i++) {
        methodUncertainty.in[i] <== in[i];
    }
    signal fix10Array[fix10Len + fix10LenVar];
    for (var i = 0; i < fix10Len + fix10LenVar; i++) {
        fix10Array[i] <== methodUncertainty.out[i];
    }


    signal output identifier;
    component fix10Regex = Fix10Regex();
    fix10Regex.encoded <== encodedLen;
    for (var i = 0; i < fix10Len + fix10LenVar; i++) {
        fix10Regex.in[i] <== fix10Array[0 + i];
    }
    identifier <== fix10Regex.out;
}
