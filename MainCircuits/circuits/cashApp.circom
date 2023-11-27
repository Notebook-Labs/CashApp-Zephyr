// SPDX-License-Identifier: BUSL-1.1

pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../dep/sha256.circom";
include "../dep/rsa.circom";
include "../dep/base64.circom";
include "../dep/utils.circom";
include "../dep/modulusHash.circom";
include "../dep/bodyHashRegex.circom";
include "./wrappers/bodySimple.circom";
include "./wrappers/bodyCredit.circom";
include "./wrappers/subjectAccept.circom";
include "./wrappers/subjectSent.circom";
include "./wrappers/subjectPaid.circom";


template cashApp(maxHeaderBytes, maxBodyBytes, n, k, keyLenBytes) {

	// support for 1024, 2048 bit rsa keys
	assert(keyLenBytes >= 128);
	assert(keyLenBytes <= 256);
	assert(keyLenBytes % 64 == 0);

	assert(maxHeaderBytes % 64 == 0);
	assert(maxHeaderBytes > 0);
	assert(maxHeaderBytes < 4096); // Just to ensure maxHeaderBits is a field element. In practice can be larger

	assert(maxBodyBytes % 64 == 0);
	assert(maxBodyBytes > 0);
	assert(maxBodyBytes < 32000); // Just to ensure maxHeaderBits is a field element. In practice can be larger

	assert(n * k > keyLenBytes * 8); // ensure we have enough bits to store the modulus
	assert(k * 2 < 255); 
	assert(k >= 0);
	assert(n >= 0);
	assert(n < 122); // not a perfect bound but we need 2n + log(k) < 254 

	var maxHeaderBits = maxHeaderBytes * 8;

	// Input selectors
    signal input subjectSelect;
    signal input bodySelect;

	//inputs for accept header
    signal input dateAcceptLen;
    signal input emailAcceptLen;
    signal input amountAcceptLen;
    signal input nameAcceptLen;

	//inputs for paid header
    signal input datePaidLen;
    signal input emailPaidLen;
    signal input amountPaidLen;
    signal input namePaidLen;

	//inputs for sent header
    signal input dateSentLen;
    signal input emailSentLen;
    signal input amountSentLen;
    signal input nameSentLen;

	//inputs for simple body regex
    signal input part0Len;
    signal input payment0Len;
    signal input photo0Len;
    signal input name0Len;
    signal input username0Len;
    signal input message0Len;
    signal input amount0Len;
    signal input method0Len;
	//this signal isn't equality checked but determines the length of the name extracted in the body. As
	//the extracted name is equality checked with the name from the subject, which is of nameLen - is secure
	//because a fix component occurs right after the name in the subject (so nameLen is constrained).
	signal input nameExtract0Len;
	signal input firstAmount0Len;
	signal input usernamePart0Len;

	//inputs for credit card body regex
    signal input part1Len;
    signal input payment1Len;
    signal input photo1Len;
    signal input name1Len;
    signal input username1Len;
    signal input message1Len;
    signal input amount1Len;
    signal input method1Len;
    signal input credit1Len;
    signal input credit2Len;
    signal input nameExtract1Len;
	signal input firstAmount1Len;
	signal input usernamePart1Len;

    signal input inPadded0[maxHeaderBytes];
    signal input inPadded1[maxHeaderBytes];
    signal input inPadded2[maxHeaderBytes];
    signal input inPadded3[maxHeaderBytes];
    signal input inPadded4[maxHeaderBytes];
    signal input inPadded5[maxHeaderBytes];
    signal input inBodyPadded0[maxBodyBytes];
    signal input inBodyPadded1[maxBodyBytes];
    signal input nonce;
    signal input proverAddress;

    var firstAmountMin = 13;
    var firstAmountMax = 24;

    component firstAmount0Check = MaxMinCheck(5, firstAmountMin, firstAmountMax);
	firstAmount0Check.inLen <== firstAmount0Len;

    component firstAmount1Check = MaxMinCheck(5, firstAmountMin, firstAmountMax);
	firstAmount1Check.inLen <== firstAmount1Len;

    var usernamePartMin = 8;
    var usernamePartMax = 31;

    component usernamePart0Check = MaxMinCheck(5, usernamePartMin, usernamePartMax);
	usernamePart0Check.inLen <== usernamePart0Len;

    component usernamePart1Check = MaxMinCheck(5, usernamePartMin, usernamePartMax);
	usernamePart1Check.inLen <== usernamePart1Len;

    signal input encoded0Len;
    signal input encoded1Len;

	encoded0Len * (1 - encoded0Len) === 0;
	encoded1Len * (1 - encoded1Len) === 0;

    var dateMin = 25;
    var dateMax = 35;
    var emailMin = 80;
    var emailMax = 600;
    var subjectAmountMin = 1;
    var subjectAmountMax = 9;
    var subjectNameMin = 2;
    var subjectNameMax = 380;
    var partMin = 280;
    var partMax = 1300;
    var paymentMin = 10;
    var paymentMax = 785;
    var photoMin = 465;
    var photoMax = 579 + 30;
    var nameMin = 20;
    var nameMax = 610;
    var usernameMin = 1;
    var usernameMax = 21;
    var messageMin = 0;
    var messageMax = 1600;
    var amountMin = 1;
    var amountMax = 9;
    var methodMin = 1;
    var methodMax = 201;
    var credit1Min = 1;
    var credit1Max = 9;
    var credit2Min = 1;
    var credit2Max = 9;
    var isCreditMin = 0;
    var isCreditMax = 1;
    var subjectMin = 0;
    var subjectMax = 2;

	component dateAcceptCheck = MaxMinCheck(6, dateMin, dateMax);
	dateAcceptCheck.inLen <== dateAcceptLen;

	component emailAcceptCheck = MaxMinCheck(10, emailMin, emailMax);
	emailAcceptCheck.inLen <== emailAcceptLen;

	component amountAcceptCheck = MaxMinCheck(5, subjectAmountMin, subjectAmountMax);
	amountAcceptCheck.inLen <== amountAcceptLen;

	component nameAcceptCheck = MaxMinCheck(9, subjectNameMin, subjectNameMax);
	nameAcceptCheck.inLen <== nameAcceptLen;

	component datePaidCheck = MaxMinCheck(6, dateMin, dateMax);
	datePaidCheck.inLen <== datePaidLen;

	component emailPaidCheck = MaxMinCheck(10, emailMin, emailMax);
	emailPaidCheck.inLen <== emailPaidLen;

	component amountPaidCheck = MaxMinCheck(5, subjectAmountMin, subjectAmountMax);
	amountPaidCheck.inLen <== amountPaidLen;

	component namePaidCheck = MaxMinCheck(9, subjectNameMin, subjectNameMax);
	namePaidCheck.inLen <== namePaidLen;

	component dateSentCheck = MaxMinCheck(6, dateMin, dateMax);
	dateSentCheck.inLen <== dateSentLen;

	component emailSentCheck = MaxMinCheck(10, emailMin, emailMax);
	emailSentCheck.inLen <== emailSentLen;

	component amountSentCheck = MaxMinCheck(5, subjectAmountMin, subjectAmountMax);
	amountSentCheck.inLen <== amountSentLen;

	component nameSentCheck = MaxMinCheck(9, subjectNameMin, subjectNameMax);
	nameSentCheck.inLen <== nameSentLen;

	component part0Check = MaxMinCheck(11, partMin, partMax);
	part0Check.inLen <== part0Len;

	component payment0Check = MaxMinCheck(10, paymentMin, paymentMax);
	payment0Check.inLen <== payment0Len;

	component photo0Check = MaxMinCheck(10, photoMin, photoMax);
	photo0Check.inLen <== photo0Len;

	component name0Check = MaxMinCheck(10, nameMin, nameMax);
	name0Check.inLen <== name0Len;

	component username0Check = MaxMinCheck(5, usernameMin, usernameMax);
	username0Check.inLen <== username0Len;

	component message0Check = MaxMinCheck(11, messageMin, messageMax);
	message0Check.inLen <== message0Len;

	component amount0Check = MaxMinCheck(5, amountMin, amountMax);
	amount0Check.inLen <== amount0Len;

	component method0Check = MaxMinCheck(8, methodMin, methodMax);
	method0Check.inLen <== method0Len;

	component part1Check = MaxMinCheck(11, partMin, partMax);
	part1Check.inLen <== part1Len;

	component payment1Check = MaxMinCheck(10, paymentMin, paymentMax);
	payment1Check.inLen <== payment1Len;

	component photo1Check = MaxMinCheck(10, photoMin, photoMax);
	photo1Check.inLen <== photo1Len;

	component name1Check = MaxMinCheck(10, nameMin, nameMax);
	name1Check.inLen <== name1Len;

	component username1Check = MaxMinCheck(5, usernameMin, usernameMax);
	username1Check.inLen <== username1Len;

	component message1Check = MaxMinCheck(11, messageMin, messageMax);
	message1Check.inLen <== message1Len;

	component amount1Check = MaxMinCheck(5, amountMin, amountMax);
	amount1Check.inLen <== amount1Len;

	component method1Check = MaxMinCheck(8, methodMin, methodMax);
	method1Check.inLen <== method1Len;

	component credit1Check = MaxMinCheck(5, credit1Min, credit1Max);
	credit1Check.inLen <== credit1Len;

	component credit2Check = MaxMinCheck(5, credit2Min, credit2Max);
	credit2Check.inLen <== credit2Len;

	component bodySelectCheck = MaxMinCheck(2, isCreditMin, isCreditMax);
	bodySelectCheck.inLen <== bodySelect;

	component subjectSelectCheck = MaxMinCheck(2, subjectMin, subjectMax);
	subjectSelectCheck.inLen <== subjectSelect;

	//
	// CHECK SUBJECT 0
	//

	component subjectAccept0 = SubjectAccept(maxHeaderBytes);
	for (var i = 0; i < maxHeaderBytes; i++) {
		subjectAccept0.in[i] <== inPadded0[i];
	}
	subjectAccept0.dateLen <== dateAcceptLen;
	subjectAccept0.emailLen <== emailAcceptLen;
	subjectAccept0.subjectAmountLen <== amountAcceptLen;
	subjectAccept0.subjectNameLen <== nameAcceptLen;

	//
	// CHECK SUBJECT 1
	//

	component subjectAccept1 = SubjectAccept(maxHeaderBytes);
	for (var i = 0; i < maxHeaderBytes; i++) {
		subjectAccept1.in[i] <== inPadded1[i];
	}
	subjectAccept1.dateLen <== dateAcceptLen;
	subjectAccept1.emailLen <== emailAcceptLen;
	subjectAccept1.subjectAmountLen <== amountAcceptLen;
	subjectAccept1.subjectNameLen <== nameAcceptLen;
	subjectAccept0.amount === subjectAccept1.amount;
	subjectAccept0.note === subjectAccept1.note;

	for (var i = 0; i < 42; i++) {
		subjectAccept0.name[i] === subjectAccept1.name[i];
	}



	//
	// CHECK SUBJECT 0
	//

	component subjectPaid0 = SubjectPaid(maxHeaderBytes);
	for (var i = 0; i < maxHeaderBytes; i++) {
		subjectPaid0.in[i] <== inPadded2[i];
	}
	subjectPaid0.dateLen <== datePaidLen;
	subjectPaid0.emailLen <== emailPaidLen;
	subjectPaid0.subjectAmountLen <== amountPaidLen;
	subjectPaid0.subjectNameLen <== namePaidLen;

	//
	// CHECK SUBJECT 1
	//

	component subjectPaid1 = SubjectPaid(maxHeaderBytes);
	for (var i = 0; i < maxHeaderBytes; i++) {
		subjectPaid1.in[i] <== inPadded3[i];
	}
	subjectPaid1.dateLen <== datePaidLen;
	subjectPaid1.emailLen <== emailPaidLen;
	subjectPaid1.subjectAmountLen <== amountPaidLen;
	subjectPaid1.subjectNameLen <== namePaidLen;
	subjectPaid0.amount === subjectPaid1.amount;
	subjectPaid0.note === subjectPaid1.note;

	for (var i = 0; i < 42; i++) {
		subjectPaid0.name[i] === subjectPaid1.name[i];
	}



	//
	// CHECK SUBJECT 0
	//

	component subjectSent0 = SubjectSent(maxHeaderBytes);
	for (var i = 0; i < maxHeaderBytes; i++) {
		subjectSent0.in[i] <== inPadded4[i];
	}
	subjectSent0.dateLen <== dateSentLen;
	subjectSent0.emailLen <== emailSentLen;
	subjectSent0.subjectAmountLen <== amountSentLen;
	subjectSent0.subjectNameLen <== nameSentLen;

	//
	// CHECK SUBJECT 1
	//

	component subjectSent1 = SubjectSent(maxHeaderBytes);
	for (var i = 0; i < maxHeaderBytes; i++) {
		subjectSent1.in[i] <== inPadded5[i];
	}
	subjectSent1.dateLen <== dateSentLen;
	subjectSent1.emailLen <== emailSentLen;
	subjectSent1.subjectAmountLen <== amountSentLen;
	subjectSent1.subjectNameLen <== nameSentLen;
	subjectSent0.amount === subjectSent1.amount;
	subjectSent0.note === subjectSent1.note;

	for (var i = 0; i < 42; i++) {
		subjectSent0.name[i] === subjectSent1.name[i];
	}




	component subjectAmountEqs[3];
	signal subjectAmountSums[3+1];
	signal subjectAmountSignals[3];

	subjectAmountSignals[0] <== subjectAccept0.amount;
	subjectAmountSignals[1] <== subjectPaid0.amount;
	subjectAmountSignals[2] <== subjectSent0.amount;
	subjectAmountSums[0] <== 0;

	for (var i = 0; i < 3; i ++) {
		subjectAmountEqs[i] = IsEqual();
		subjectAmountEqs[i].in[0] <== i;
		subjectAmountEqs[i].in[1] <== subjectSelect;

		subjectAmountSums[i+1] <== subjectAmountSums[i] + subjectAmountEqs[i].out * subjectAmountSignals[i];

	}

	signal subjectAmount <== subjectAmountSums[3];



	component subjectNoteEqs[3];
	signal subjectNoteSums[3+1];
	signal subjectNoteSignals[3];

	subjectNoteSignals[0] <== subjectAccept0.note;
	subjectNoteSignals[1] <== subjectPaid0.note;
	subjectNoteSignals[2] <== subjectSent0.note;
	subjectNoteSums[0] <== 0;

	for (var i = 0; i < 3; i ++) {
		subjectNoteEqs[i] = IsEqual();
		subjectNoteEqs[i].in[0] <== i;
		subjectNoteEqs[i].in[1] <== subjectSelect;

		subjectNoteSums[i+1] <== subjectNoteSums[i] + subjectNoteEqs[i].out * subjectNoteSignals[i];

	}

	signal subjectNote <== subjectNoteSums[3];



	component subjectNameEqs[3];
	signal subjectNameSums[42][3+1];
	signal subjectNameArrays[3][42];

	for (var k=0; k<42; k++) {
		subjectNameArrays[0][k] <== subjectAccept0.name[k];
		subjectNameArrays[1][k] <== subjectPaid0.name[k];
		subjectNameArrays[2][k] <== subjectSent0.name[k];
	}

	for (var k=0; k<42; k++) {
		subjectNameSums[k][0] <== 0;
	}

	for (var i = 0; i < 3; i ++) {
		subjectNameEqs[i] = IsEqual();
		subjectNameEqs[i].in[0] <== i;
		subjectNameEqs[i].in[1] <== subjectSelect;

		for (var k=0; k<42; k++) {
			subjectNameSums[k][i+1] <== subjectNameSums[k][i] + subjectNameEqs[i].out * subjectNameArrays[i][k];
		}

	}

	// output the final sums
	signal subjectName[42];
	for (var k=0; k<42; k++) {
		subjectName[k] <== subjectNameSums[k][3];
	}


	//
	// BODY REGEX AND EXTRACTION
	//

	component bodySimple = BodySimple(maxBodyBytes);
	for (var i = 0; i < maxBodyBytes; i++) {
		bodySimple.in[i] <== inBodyPadded0[i];
	}

	bodySimple.partLen <== part0Len;
	bodySimple.paymentLen <== payment0Len;
	bodySimple.photoLen <== photo0Len;
	bodySimple.nameLen <== name0Len;
	bodySimple.usernameLen <== username0Len;
	bodySimple.messageLen <== message0Len;
	bodySimple.amountLen <== amount0Len;
	bodySimple.methodLen <== method0Len;
	bodySimple.nameExtractLen <== nameExtract0Len;
    bodySimple.firstAmountLen <== firstAmount0Len;
    bodySimple.usernamePartLen <== usernamePart0Len;
    bodySimple.encodedLen <== encoded0Len;



	//
	// PACK NECESSARY ARRAY OUTPUTS
	//

	signal packBodySimpleUsername <== Bytes2Packed(21, bodySimple.username);



	//
	// BODY REGEX AND EXTRACTION
	//

	component bodyCredit = BodyCredit(maxBodyBytes);
	for (var i = 0; i < maxBodyBytes; i++) {
		bodyCredit.in[i] <== inBodyPadded1[i];
	}

	bodyCredit.partLen <== part1Len;
	bodyCredit.paymentLen <== payment1Len;
	bodyCredit.photoLen <== photo1Len;
	bodyCredit.nameLen <== name1Len;
	bodyCredit.usernameLen <== username1Len;
	bodyCredit.messageLen <== message1Len;
	bodyCredit.amountLen <== amount1Len;
	bodyCredit.methodLen <== method1Len;
	bodyCredit.credit1Len <== credit1Len;
	bodyCredit.credit2Len <== credit2Len;
	bodyCredit.nameExtractLen <== nameExtract1Len;
    bodyCredit.firstAmountLen <== firstAmount1Len;
    bodyCredit.usernamePartLen <== usernamePart1Len;
    bodyCredit.encodedLen <== encoded1Len;



	//
	// PACK NECESSARY ARRAY OUTPUTS
	//

	signal packBodyCreditUsername <== Bytes2Packed(21, bodyCredit.username);




	component bodyNoteEqs[2];
	signal bodyNoteSums[2+1];
	signal bodyNoteSignals[2];

	bodyNoteSignals[0] <== bodySimple.note;
	bodyNoteSignals[1] <== bodyCredit.note;
	bodyNoteSums[0] <== 0;

	for (var i = 0; i < 2; i ++) {
		bodyNoteEqs[i] = IsEqual();
		bodyNoteEqs[i].in[0] <== i;
		bodyNoteEqs[i].in[1] <== bodySelect;

		bodyNoteSums[i+1] <== bodyNoteSums[i] + bodyNoteEqs[i].out * bodyNoteSignals[i];

	}

	signal bodyNote <== bodyNoteSums[2];



	component bodyAmountEqs[2];
	signal bodyAmountSums[2+1];
	signal bodyAmountSignals[2];

	bodyAmountSignals[0] <== bodySimple.amount;
	bodyAmountSignals[1] <== bodyCredit.amount;
	bodyAmountSums[0] <== 0;

	for (var i = 0; i < 2; i ++) {
		bodyAmountEqs[i] = IsEqual();
		bodyAmountEqs[i].in[0] <== i;
		bodyAmountEqs[i].in[1] <== bodySelect;

		bodyAmountSums[i+1] <== bodyAmountSums[i] + bodyAmountEqs[i].out * bodyAmountSignals[i];

	}

	signal bodyAmount <== bodyAmountSums[2];



	component identifierEqs[2];
	signal identifierSums[2+1];
	signal identifierSignals[2];

	identifierSignals[0] <== bodySimple.identifier;
	identifierSignals[1] <== bodyCredit.identifier;
	identifierSums[0] <== 0;

	for (var i = 0; i < 2; i ++) {
		identifierEqs[i] = IsEqual();
		identifierEqs[i].in[0] <== i;
		identifierEqs[i].in[1] <== bodySelect;

		identifierSums[i+1] <== identifierSums[i] + identifierEqs[i].out * identifierSignals[i];

	}

	signal identifier <== identifierSums[2];



	component usernameEqs[2];
	signal usernameSums[2+1];
	signal usernameSignals[2];

	usernameSignals[0] <== packBodySimpleUsername;
	usernameSignals[1] <== packBodyCreditUsername;
	usernameSums[0] <== 0;

	for (var i = 0; i < 2; i ++) {
		usernameEqs[i] = IsEqual();
		usernameEqs[i].in[0] <== i;
		usernameEqs[i].in[1] <== bodySelect;

		usernameSums[i+1] <== usernameSums[i] + usernameEqs[i].out * usernameSignals[i];

	}

	signal username <== usernameSums[2];



	component bodyNameEqs[2];
	signal bodyNameSums[42][2+1];
	signal bodyNameArrays[2][42];

	for (var k=0; k<42; k++) {
		bodyNameArrays[0][k] <== bodySimple.name[k];
		bodyNameArrays[1][k] <== bodyCredit.name[k];
	}

	for (var k=0; k<42; k++) {
		bodyNameSums[k][0] <== 0;
	}

	for (var i = 0; i < 2; i ++) {
		bodyNameEqs[i] = IsEqual();
		bodyNameEqs[i].in[0] <== i;
		bodyNameEqs[i].in[1] <== bodySelect;

		for (var k=0; k<42; k++) {
			bodyNameSums[k][i+1] <== bodyNameSums[k][i] + bodyNameEqs[i].out * bodyNameArrays[i][k];
		}

	}

	// output the final sums
	signal bodyName[42];
	for (var k=0; k<42; k++) {
		bodyName[k] <== bodyNameSums[k][2];
	}


	subjectAmount === bodyAmount;

	subjectNote === bodyNote;

	for (var i = 0; i < 42; i++) {
		subjectName[i] === bodyName[i];
	}



	component inSubject0Eqs[3];
	signal inSubject0Sums[maxHeaderBytes][3+1];
	signal inSubject0Arrays[3][maxHeaderBytes];

	for (var k=0; k<maxHeaderBytes; k++) {
		inSubject0Arrays[0][k] <== inPadded0[k];
		inSubject0Arrays[1][k] <== inPadded2[k];
		inSubject0Arrays[2][k] <== inPadded4[k];
	}

	for (var k=0; k<maxHeaderBytes; k++) {
		inSubject0Sums[k][0] <== 0;
	}

	for (var i = 0; i < 3; i ++) {
		inSubject0Eqs[i] = IsEqual();
		inSubject0Eqs[i].in[0] <== i;
		inSubject0Eqs[i].in[1] <== subjectSelect;

		for (var k=0; k<maxHeaderBytes; k++) {
			inSubject0Sums[k][i+1] <== inSubject0Sums[k][i] + inSubject0Eqs[i].out * inSubject0Arrays[i][k];
		}

	}

	// output the final sums
	signal inSubject0[maxHeaderBytes];
	for (var k=0; k<maxHeaderBytes; k++) {
		inSubject0[k] <== inSubject0Sums[k][3];
	}



	component inSubject1Eqs[3];
	signal inSubject1Sums[maxHeaderBytes][3+1];
	signal inSubject1Arrays[3][maxHeaderBytes];

	for (var k=0; k<maxHeaderBytes; k++) {
		inSubject1Arrays[0][k] <== inPadded1[k];
		inSubject1Arrays[1][k] <== inPadded3[k];
		inSubject1Arrays[2][k] <== inPadded5[k];
	}

	for (var k=0; k<maxHeaderBytes; k++) {
		inSubject1Sums[k][0] <== 0;
	}

	for (var i = 0; i < 3; i ++) {
		inSubject1Eqs[i] = IsEqual();
		inSubject1Eqs[i].in[0] <== i;
		inSubject1Eqs[i].in[1] <== subjectSelect;

		for (var k=0; k<maxHeaderBytes; k++) {
			inSubject1Sums[k][i+1] <== inSubject1Sums[k][i] + inSubject1Eqs[i].out * inSubject1Arrays[i][k];
		}

	}

	// output the final sums
	signal inSubject1[maxHeaderBytes];
	for (var k=0; k<maxHeaderBytes; k++) {
		inSubject1[k] <== inSubject1Sums[k][3];
	}



	component inBodyEqs[2];
	signal inBodySums[maxBodyBytes][2+1];
	signal inBodyArrays[2][maxBodyBytes];

	for (var k=0; k<maxBodyBytes; k++) {
		inBodyArrays[0][k] <== inBodyPadded0[k];
		inBodyArrays[1][k] <== inBodyPadded1[k];
	}

	for (var k=0; k<maxBodyBytes; k++) {
		inBodySums[k][0] <== 0;
	}

	for (var i = 0; i < 2; i ++) {
		inBodyEqs[i] = IsEqual();
		inBodyEqs[i].in[0] <== i;
		inBodyEqs[i].in[1] <== bodySelect;

		for (var k=0; k<maxBodyBytes; k++) {
			inBodySums[k][i+1] <== inBodySums[k][i] + inBodyEqs[i].out * inBodyArrays[i][k];
		}

	}

	// output the final sums
	signal inBody[maxBodyBytes];
	for (var k=0; k<maxBodyBytes; k++) {
		inBody[k] <== inBodySums[k][2];
	}

	//
	// CHECK INPUTS AND HASH
	//

	signal input inLenPaddedBytes0; // length of in header data including the padding

	component sha0 = sha256(maxHeaderBits);

	// Need to input bits to sha256. Also servers as a range check
	component inPadded0Bits[maxHeaderBytes];

	for (var i = 0; i < maxHeaderBytes; i++) {
		inPadded0Bits[i] = Num2Bits(8);
		inPadded0Bits[i].in <== inSubject0[i];

		for (var j = 0; j < 8; j++) {
			// we need to unflip the bits as sha0 treats the first bit as the MSB
			sha0.paddedIn[i*8+j] <== inPadded0Bits[i].out[7-j]; 
		}
	}

	sha0.inLenPaddedBits <== inLenPaddedBytes0 * 8;

	//
	// VERIFY RSA SIGNATURE
	//

	// pubkey, verified with smart contract oracle
	signal input modulus0[k]; 
	signal input signature0[k];

	// range check the public key
	component modulus0RangeCheck[k];
	for (var i = 0; i < k; i++) {
		modulus0RangeCheck[i] = Num2Bits(n);
		modulus0RangeCheck[i].in <== modulus0[i];
	}

	// range check the signature
	component signature0RangeCheck[k];
	for (var i = 0; i < k; i++) {
		signature0RangeCheck[i] = Num2Bits(n);
		signature0RangeCheck[i].in <== signature0[i];
	}

	// verify the rsa signature of the first key
	component rsa0 = RSAVerify65537(n, k, keyLenBytes);
	for (var i = 0; i < 256; i++) {
		rsa0.baseMessage[i] <== sha0.out[i];
	}
	for (var i = 0; i < k; i++) {
		rsa0.modulus[i] <== modulus0[i];
	}
	for (var i = 0; i < k; i++) {
		rsa0.signature[i] <== signature0[i];
	}

	//
	// CHECK INPUTS AND HASH
	//

	signal input inLenPaddedBytes1; // length of in header data including the padding

	component sha1 = sha256(maxHeaderBits);

	// Need to input bits to sha256. Also servers as a range check
	component inPadded1Bits[maxHeaderBytes];

	for (var i = 0; i < maxHeaderBytes; i++) {
		inPadded1Bits[i] = Num2Bits(8);
		inPadded1Bits[i].in <== inSubject1[i];

		for (var j = 0; j < 8; j++) {
			// we need to unflip the bits as sha1 treats the first bit as the MSB
			sha1.paddedIn[i*8+j] <== inPadded1Bits[i].out[7-j]; 
		}
	}

	sha1.inLenPaddedBits <== inLenPaddedBytes1 * 8;

	//
	// VERIFY RSA SIGNATURE
	//

	// pubkey, verified with smart contract oracle
	signal input modulus1[k]; 
	signal input signature1[k];

	// range check the public key
	component modulus1RangeCheck[k];
	for (var i = 0; i < k; i++) {
		modulus1RangeCheck[i] = Num2Bits(n);
		modulus1RangeCheck[i].in <== modulus1[i];
	}

	// range check the signature
	component signature1RangeCheck[k];
	for (var i = 0; i < k; i++) {
		signature1RangeCheck[i] = Num2Bits(n);
		signature1RangeCheck[i].in <== signature1[i];
	}

	// verify the rsa signature of the first key
	component rsa1 = RSAVerify65537(n, k, keyLenBytes);
	for (var i = 0; i < 256; i++) {
		rsa1.baseMessage[i] <== sha1.out[i];
	}
	for (var i = 0; i < k; i++) {
		rsa1.modulus[i] <== modulus1[i];
	}
	for (var i = 0; i < k; i++) {
		rsa1.signature[i] <== signature1[i];
	}

	//
	// HASH PUBLIC KEYS 
	//

	component shaMod = ModulusSha(n, k, keyLenBytes);
	for (var i = 0; i < k; i++) {
		shaMod.modulus0[i] <== modulus0[i];
	}

	for (var i = 0; i < k; i++) {
		shaMod.modulus1[i] <== modulus1[i];
	}

	//
	// BODY HASH REGEX 0: 
	//

	var lenShaB64 = 44;  
	component bodyHashRegex0 = BodyHashRegex(maxHeaderBytes, lenShaB64);
	for (var i = 0; i < maxHeaderBytes; i++) {
		bodyHashRegex0.msg[i] <== inSubject0[i];
	}

	//
	// BODY HASH REGEX 1: 
	//

	component bodyHashRegex1 = BodyHashRegex(maxHeaderBytes, lenShaB64);
	for (var i = 0; i < maxHeaderBytes; i++) {
		bodyHashRegex1.msg[i] <== inSubject1[i];
	}

	//
	// EQUALITY CHECK EXTRACT BODY HASHES
	//

	for (var i = 0; i < lenShaB64; i++) {
		bodyHashRegex0.bodyHashOut[i] === bodyHashRegex1.bodyHashOut[i];
	}

	//
	// HASH BODY
	//

	signal input inBodyLenPaddedBytes;

	var maxBodyBits = maxBodyBytes * 8;
	component shaBody = sha256(maxBodyBits);

	// Need to input bits to sha256. Also servers as a range check
	component inBodyPaddedBits[maxBodyBytes];

	for (var i = 0; i < maxBodyBytes; i++) {
		inBodyPaddedBits[i] = Num2Bits(8);
		inBodyPaddedBits[i].in <== inBody[i];

		for (var j = 0; j < 8; j++) {
			// we need to unflip the bits as sha256 treats the first bit as the MSB
			shaBody.paddedIn[i*8+j] <== inBodyPaddedBits[i].out[7-j]; 
		}
	}

	shaBody.inLenPaddedBits <== inBodyLenPaddedBytes * 8;

	//
	// VERIFY HASH OF BODY MATCHES BODY HASH EXTRACTED FROM HEADER 
	//

	component shaB64 = Base64Decode(lenShaB64); 
	for (var i = 0; i < lenShaB64; i++) {
		shaB64.in[i] <== bodyHashRegex0.bodyHashOut[i];
	}

	for (var i = 0; i < 256; i++) {
		shaB64.out[i] === shaBody.out[i];
	}



	component sellerHashHasher = Poseidon(2);
	sellerHashHasher.inputs[0] <== username;
	sellerHashHasher.inputs[1] <== nonce;
	signal sellerHash <== sellerHashHasher.out;


	component nullifierHasher = Poseidon(3);
	nullifierHasher.inputs[0] <== identifier;
	nullifierHasher.inputs[1] <== username;
	nullifierHasher.inputs[2] <== bodyAmount;
	signal nullifier <== nullifierHasher.out;


	//
	// COMPUTE THE OUTPUTTED COMMITMENT
	//

	component megaHash = Sha256(1088);

	// add modulus hash to mega hash
	for (var i = 0; i < 256; i++) {
		megaHash.in[i] <== shaMod.out[i];
	}

	component sellerHashBits256 = Num2Bits(256);
	sellerHashBits256.in <== sellerHash;
	for (var i = 0; i < 256; i++) {
		megaHash.in[256 + i] <== sellerHashBits256.out[256 - 1 - i];
	}

	component nullifierBits256 = Num2Bits(256);
	nullifierBits256.in <== nullifier;
	for (var i = 0; i < 256; i++) {
		megaHash.in[512 + i] <== nullifierBits256.out[256 - 1 - i];
	}

	component proverAddressBits160 = Num2Bits(160);
	proverAddressBits160.in <== proverAddress;
	for (var i = 0; i < 160; i++) {
		megaHash.in[768 + i] <== proverAddressBits160.out[160 - 1 - i];
	}

	component bodyNoteBits64 = Num2Bits(64);
	bodyNoteBits64.in <== bodyNote;
    log("bodynote");
    log(bodyNote);
	for (var i = 0; i < 64; i++) {
		megaHash.in[928 + i] <== bodyNoteBits64.out[64 - 1 - i];
	}

	component bodyAmountBits32 = Num2Bits(32);
	bodyAmountBits32.in <== bodyAmount;
    log("bodyamount");
    log(bodyAmount);
	for (var i = 0; i < 32; i++) {
		megaHash.in[992 + i] <== bodyAmountBits32.out[32 - 1 - i];
	}

	component identifierBits64 = Num2Bits(64);
	identifierBits64.in <== identifier;
    log("identifier");
    log(identifier);
	for (var i = 0; i < 64; i++) {
		megaHash.in[1024 + i] <== identifierBits64.out[64 - 1 - i];
	}

	signal output outputHash;

    log("Hash");
	component megaHashBits2Num = Bits2Num(253);
	for (var i = 0; i < 253; i++) {
		megaHashBits2Num.in[i] <== megaHash.out[252 - i];
        log(megaHash.out[252 - i]);
	}

	outputHash <== megaHashBits2Num.out;

}


component main = cashApp(1728, 26240, 121, 9, 128);