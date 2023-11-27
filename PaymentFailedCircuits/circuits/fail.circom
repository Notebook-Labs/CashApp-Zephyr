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
include "./wrappers/body.circom";
include "./wrappers/subject.circom";


template fail(maxHeaderBytes, maxBodyBytes, n, k, keyLenBytes) {

	// support for 1024, 2048 bit rsa keys
	assert(keyLenBytes >= 128);
	assert(keyLenBytes <= 256);
	assert(keyLenBytes % 64 == 0);

	assert(maxHeaderBytes % 64 == 0);
	assert(maxHeaderBytes > 0);
	assert(maxHeaderBytes < 4096); // Just to ensure maxHeaderBits is a field element. In practice can be larger

	assert(maxBodyBytes % 64 == 0);
	assert(maxBodyBytes > 0);
	assert(maxBodyBytes < 51200); // Just to ensure maxHeaderBits is a field element. In practice can be larger

	assert(n * k > keyLenBytes * 8); // ensure we have enough bits to store the modulus
	assert(k * 2 < 255); 
	assert(k >= 0);
	assert(n >= 0);
	assert(n < 122); // not a perfect bound but we need 2n + log(k) < 254 

	var maxHeaderBits = maxHeaderBytes * 8;

    signal input encodedLen;
    var encodedMin = 0;
    var encodedMax = 1;

    component encodedCheck = MaxMinCheck(1, encodedMin, encodedMax);
	encodedCheck.inLen <== encodedLen;

    signal input dateLen;
    signal input emailLen;
    signal input partLen;
    signal input paymentLen;
    signal input coreLen;
    signal input postLen;
    signal input inPadded0[maxHeaderBytes];
    signal input inPadded1[maxHeaderBytes];
    signal input inBodyPadded0[maxBodyBytes];
    signal input proverAddress;

    var dateMin = 25;
    var dateMax = 35;
    var emailMin = 80;
    var emailMax = 600;
    var partMin = 220;
    var partMax = 1420;
    var paymentMin = 10;
    var paymentMax = 785;
    var coreMin = 0;
    var coreMax = 5000;
    var postMin = 0;
    var postMax = 9000;



	component dateCheck = MaxMinCheck(6, dateMin, dateMax);
	dateCheck.inLen <== dateLen;

	component emailCheck = MaxMinCheck(10, emailMin, emailMax);
	emailCheck.inLen <== emailLen;

	component partCheck = MaxMinCheck(11, partMin, partMax);
	partCheck.inLen <== partLen;

	component paymentCheck = MaxMinCheck(10, paymentMin, paymentMax);
	paymentCheck.inLen <== paymentLen;

	component coreCheck = MaxMinCheck(13, coreMin, coreMax);
	coreCheck.inLen <== coreLen;

	component postCheck = MaxMinCheck(14, postMin, postMax);
	postCheck.inLen <== postLen;

	//
	// CHECK SUBJECT 0
	//

	component subject0 = Subject(maxHeaderBytes);
	for (var i = 0; i < maxHeaderBytes; i++) {
		subject0.in[i] <== inPadded0[i];
	}
	subject0.dateLen <== dateLen;
	subject0.emailLen <== emailLen;

	//
	// CHECK SUBJECT 1
	//

	component subject1 = Subject(maxHeaderBytes);
	for (var i = 0; i < maxHeaderBytes; i++) {
		subject1.in[i] <== inPadded1[i];
	}
	subject1.dateLen <== dateLen;
	subject1.emailLen <== emailLen;



	//
	// BODY REGEX AND EXTRACTION
	//

	component body = Body(maxBodyBytes);
	for (var i = 0; i < maxBodyBytes; i++) {
		body.in[i] <== inBodyPadded0[i];
	}

	body.partLen <== partLen;
	body.paymentLen <== paymentLen;
	body.coreLen <== coreLen;
	body.postLen <== postLen;
    body.encodedLen <== encodedLen;





	//
	// CHECK INPUTS AND HASH
	//

	signal input inLenPaddedBytes0; // length of in header data including the padding

	component sha0 = sha256(maxHeaderBits);

	// Need to input bits to sha256. Also servers as a range check
	component inPadded0Bits[maxHeaderBytes];

	for (var i = 0; i < maxHeaderBytes; i++) {
		inPadded0Bits[i] = Num2Bits(8);
		inPadded0Bits[i].in <== inPadded0[i];

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
		inPadded1Bits[i].in <== inPadded1[i];

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
		bodyHashRegex0.msg[i] <== inPadded0[i];
	}

	//
	// BODY HASH REGEX 1: 
	//

	component bodyHashRegex1 = BodyHashRegex(maxHeaderBytes, lenShaB64);
	for (var i = 0; i < maxHeaderBytes; i++) {
		bodyHashRegex1.msg[i] <== inPadded1[i];
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
		inBodyPaddedBits[i].in <== inBodyPadded0[i];

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



	//
	// COMPUTE THE OUTPUTTED COMMITMENT
	//

	component megaHash = Sha256(480);

	// add modulus hash to mega hash
	for (var i = 0; i < 256; i++) {
		megaHash.in[i] <== shaMod.out[i];
	}

	component proverAddressBits160 = Num2Bits(160);
	proverAddressBits160.in <== proverAddress;
	for (var i = 0; i < 160; i++) {
		megaHash.in[256 + i] <== proverAddressBits160.out[160 - 1 - i];
	}

	component identifierBits64 = Num2Bits(64);
	identifierBits64.in <== body.identifier;
	for (var i = 0; i < 64; i++) {
		megaHash.in[416 + i] <== identifierBits64.out[64 - 1 - i];
	}

	signal output outputHash;

	component megaHashBits2Num = Bits2Num(253);
	for (var i = 0; i < 253; i++) {
		megaHashBits2Num.in[i] <== megaHash.out[252 - i];
	}

	outputHash <== megaHashBits2Num.out;
}


component main = fail(1344, 27648, 121, 9, 128);