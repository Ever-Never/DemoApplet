demScript = new ShellScript();
mainProcedure();

var mod;
var exp;
var data;
var response;
var plainText;
var keypairType;
var rsaPublicModulus;
var rsaPublicExponent;


function execute(command) {
	response = demScript.send(command);
//	demScript.assertSW('9000');
}

function show(show) {
	demScript.print(show);
}

function mainProcedure() {
	show('\n\nFor key Wrap/Unwrap two techniques will be used: Symmetric and Asymmetric key wrapping.'
			+'We need DES/AES key and RSA key-pair for Confidentiality(key wrap) operation,'
			+'wrapping Algorithm and Plain Text.\n'
			+'We will do the following steps...\n '
			+'For Symmetric key wrapping: \n'
			+'1. Restore MSE with Cipher(Confidentiality) algorithm: ALG_AES_BLOCK_128_CBC_NOPAD\n'
			+'2. Put AES-128 key into DEM-KEY-WRAP key container\n'
			+'3. Do Wrap-Unwrap!\n'
			+'For Asymmetric key wrapping: \n'
			+'1. SET MSE with Cipher(Confidentiality) Algorithm: ALG_RSA_PKCS1  \n'
			+'2. Generate RSA key-pair for Wrap/Unwrap\n'
			+'3. GET the Public Key \n'
			+'4. Put the Public Key into DEM-3P-PUB-KEY container\n'
			+'5. Do Wrap-Unwrap(Asymmetric)!');
	
	plainText='Kona Software Lab Limited, Dhaka';
	data = ascii2Hex(plainText);
	show('\nPlain Text is : '+ plainText);
	show('Plain Text in Hex : '+ data);
	
	show('\nRESTOREing MSE...');
	restoreMSE();
	
	putWrapKey();
	
	symmetricWrapUnwrap();
	
	show('\nSETing MSE with Cipher(Confidentiality) Algorithm: ALG_RSA_PKCS1');
	execute("00 22 F1 B8 03 8001 12");
	keypairType = '02';
	show('\nGenerating RSA key-pair for Wrap/Unwrap...');
	generateKeyPair();
	mod = '70';
	exp = '80';
	show('\Getting Generated RSA Public-key...');
	getRSAPublicKey();	
	show('\nPutting Generated RSA Public-key into DEM-3P-PUB key container...');
	putGeneratedRSAPublicKey();
	
	asymmetricWrapUnwrap();
}

function restoreMSE() {
	show('\nRESET MSE ...');
	execute("00 22 F300 00");
}

function putWrapKey() {
	show('\nPut Data : DEM_WRAP Key - AES-128 Key');
	execute("00 DA 01 11 10 00F59E5C63934FD0EFD90B057D1A2AD1");
}

function generateKeyPair(){
	execute("00 46 0000 01 "+keypairType);
}

function getRSAPublicKey(){
	show('\nGet Data : RSA Public Key Modulus...');
	execute("00 CA 01"+ mod+ "00");
	rsaPublicModulus = response;
	
	show('\nGet Data : RSA Public Key Exponent...');
	execute("00 CA 01"+ exp + "00");
	rsaPublicExponent = response;
}

function getECPublicKey(){
	show('\nGet Data : EC Public Key');
	execute("00 CA 01 60 00");
	ecPublicKey = response;
}

function putGeneratedRSAPublicKey() {
	var modulusLen = rsaPublicModulus.length/2;
	execute("00DA 0132" + intToHexConvert((modulusLen/2)+1) + "81" + rsaPublicModulus.substring(0,modulusLen));

	execute("00DA 0132" + intToHexConvert((modulusLen/2)+1) + "82" + rsaPublicModulus.substring(modulusLen, (modulusLen*2)));

	execute("00da 0134" + intToHexConvert(rsaPublicExponent.length/2) + rsaPublicExponent);
}

function symmetricWrapUnwrap() {
	show('****************************** SYMMETRIC KEY WRAP SERVICE: STARTs ******************************');
	show('\nPlain Text is :' + plainText);
	show('\nWrap ...');
	execute("00 2A 8680"+intToHexConvert(data.length/2 +1) + "40" + data);
	
	show('\nUnwrap ...');
	show('Send cipher Data ...');
	var wrapData = "00 2A 8086"+ intToHexConvert(response.length/2) + response;
	execute(wrapData);
	show('Decipher ASCII/Plain value : '+ hex2ASCII(response));
	show('******************************SYMMETRIC KEY WRAP SERVICE: END ******************************');
}

function asymmetricWrapUnwrap() {
	show('****************************** ASYMMETRIC KEY WRAP SERVICE: STARTs ******************************');
	show('\nPlain Text is :' + plainText);
	show('\nWrap ...');
	execute("00 2A 8680"+intToHexConvert(data.length/2 +1) + "40" + data);
	
	show('\nUnwrap ...');
	var wrapData = response;
	var length = wrapData.length/2;
	show('\nSend first part of encrypted msg...');
	execute("002A 8086"+ intToHexConvert(length/2 +1) +"20" + wrapData.substring(0,length));
	show('\nSend last part of encrypted msg and unwrap...');
	execute("002A 8086"+ intToHexConvert(length/2 +1) +"40" + wrapData.substring(length, (length*2)));
	
	show('Decipher ASCII/Plain value : '+ hex2ASCII(response));
	show('******************************ASYMMETRIC KEY WRAP SERVICE: END ******************************');
}

function intToHexConvert(integer){
	var str = integer.toString(16);
	return str.length ==1? "0"+str : str;
}

function hex2ASCII(hexx){
	var hex = hexx.toString();
	var str = '';
	for(var i=0; i<hex.length; i+=2)
		str+=String.fromCharCode(parseInt(hex.substr(i,2),16));
	return str;
}

function ascii2Hex(inputStr){
	var str = '';
	var i;
	for(i = 0; i<inputStr.length; i+=1)
		str += inputStr.charCodeAt(i).toString(16);
	return str.toUpperCase();
}