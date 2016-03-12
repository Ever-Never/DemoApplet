/**
 *	DemoApplet Test Script
 *	@author: Mostak Ahmed
 */
{
	konaScript = new ShellScript();
	konaScript.reset();
	konaScript.select('A000000151000000');
	konaScript.auth();
	mainProcedure();
}

var response;
var algRef;
var data;
var keypairType;
var ecPublicKey;
var rsaPublicModulus;
var rsaPublicExponent;
var rsaKeyPairGenerate;
var ecKeyPairGenerate;

function execute(command) {
	response = konaScript.send(command);
	konaScript.assertSW('9000');
}

function show(show) {
	konaScript.print(show);
}

function mainProcedure() {
	freeMemory();
	show('\nWelcome to DemoApplet Operations Test Program!');
	selectApplet();
	secureChannel();
	
	var plainText='Kona Software Lab Limited, Dhaka';
	data = ascii2Hex(plainText);
	show('\nPlain Text : '+ plainText);
	show('Plain Text Hex : '+ data);

	show('\nRESET MSE ...');
	execute("00 22 F300 00");
	putDataLoadKey();
	makeHASH();
	wrapUnwrap();
	
	messageAuthenticateSerivce();
	
	keypairType ='01';
	generateKeyPair();
	putGeneratedRSAPublicKey();
	digitalSignatureRSA();
	
	for(i = 18; i<=21; i++){
		keypairType =intToHexConvert(i);
		generateKeyPair();
		putGeneratedECPublicKey();
		digitalSignatureEC();
	}
	selectISD();
	secureChannel();
	freeMemory();
}

function selectApplet(){
	show('\nSelecting DemoApplet...');
	execute("00 a4 04 00 0B 6B6F6E61736C6669707300 00");
}

function selectISD(){
	show('\nSelecting ISD...');
	execute(" 00A4040008A00000015100000000");
}

function secureChannel(){
	show('\nCreate Secure Channel...');
	var hostChallenge = 'a1a2a3a4a5a6a7a8';
	show('\nInitialize Update...');
	execute('8050000008' + hostChallenge + '00');
	var sequenceCounter = subbytes(response, 12, 2);
	var cardChallenge 	= subbytes(response, 14, 6); 
	var cardCryptogram 	= subbytes(response, 20, 8);

	var baseKey = '404142434445464748494a4b4c4d4e4f4041424344454647';
	var padding = '000000000000000000000000';
	var icv		= '0000000000000000';

	var eNCSessionkeyderivationData = '0182' + sequenceCounter + padding;
	var eNCSessionKey = tdes_cbc_icv(eNCSessionkeyderivationData, baseKey, icv);

	var cMACSessionkeyderivationData = '0101' + sequenceCounter + padding;
	var cMACSessionKey = tdes_cbc_icv(cMACSessionkeyderivationData, baseKey, icv);

	padding = '8000000000000000';
	var CardCryptogramData = hostChallenge + sequenceCounter + cardChallenge + padding;
	var generatedCardCryptogram = subbytes(tdes_cbc_icv(CardCryptogramData, eNCSessionKey, icv),16,8);
	konaScript.assertEquals(cardCryptogram, generatedCardCryptogram);

	var HostCryptogramData = sequenceCounter + cardChallenge + hostChallenge + padding;
	var HostCryptogram = subbytes(tdes_cbc_icv(HostCryptogramData, eNCSessionKey, icv),16,8);
	
	var cMACData = '8482000010' + HostCryptogram + '800000';
	var firstPart = des_cbc(subbytes(cMACData,0,8), subbytes(cMACSessionKey,0,8));
	var cMAC = tdes_cbc_icv(subbytes(cMACData,8,8), cMACSessionKey + subbytes(cMACSessionKey,8,8), firstPart);
	show('\nExternal Authentication...');
	execute('8482000010' + HostCryptogram + cMAC);
}

function freeMemory(){
	show("\nThe available E2P size......")
	execute("B002000000");
	show("Free Memory : "+response.substring(8,12));
}

function generateRSAKeyPair(){
	show('\nGenerate RSA 2048-bit Key-Pair Generation');
	execute("00 46 0000 01 01");
	show("Modulus # "+response);
	execute("00 C0 0000 03");
	show("Exponent # "+response);
}

function generateKeyPair(){
	show('\nKey-Pair Generation');
	execute("00 46 0000 01 "+keypairType);
	if(keypairType=='01'){
		show('\nRSA Key Pair');
		getRSAPublicKey();
		rsaKeyPairGenerate =1;
	}else{
		show('\nEC Key Pair');
		getECPublicKey();
		ecKeyPairGenerate =1;
	}
}


function putDataLoadKey() {
	//Auth Key
	show('\nPut Data : DEM_Auth Key - DES Key');
	execute("00 DA 0101 10 4041424345464748494A4B4C4D4E4F");
	
	//WRAP Key
	show('\nPut Data : DEM_WRAP Key - DES Key');
	execute("00 DA 0114 10 7A8ADF648C8FA8F1A8C7852CDC89E640");
	
	//MAC Key
	show('\nPut Data : DEM_MAC Key - DES Key');
	execute("00 DA 0121 10 7A8ADF648C8FA8F1A8C7852CDC89E640");
	
	show('\nPut Data AES Key');
	execute("00 DA 0122 10 7A8ADF648C8FA8F1A8C7852CDC89E640");

	show('\nPut Data HMAC Key');
	execute("00 DA 0123 20 6AB8855EC63C8CB3C19B7A0E14384C92F161BE5B03DF4575FEC7A757F36CC313");

	//3P Public Key
	show('\nPut Data : DEM_RSA_PUB Key - 3P Public Key (2048 bits) ...');
	execute("00da 0132 81 81 9CBDC33F870F25F5BCFCA50890F0296B584A338AE2BB3EDE567F2F4620AA46BF5F3080133EBD8A2357E01A4783E40EC0ABF1D51A6D31713E6DDB79DC3638AF5A5B08C2DB18EDEBFB15EE2A1A6BC3E895CFA1E2601CAB0CC284E44A8C182C1298AF21A9286AFBA4EF3C89FEE87ECC3D1A1C0A74E5B6AD7E13BBA5B625721E4B89");
	execute("00da 0132 81 82 18E785C2E41A5E2B323919E7F23FD25232EAAFDCBAA807191E95C7DEDF0F9E824EECBAC42E58E1992308396BC888C92CA3A8188526AA32B401B2DC64BE8D0CDFBD2797ED8BABF8196B34EFFE6B6C400444534D3228FE6C2E5C5A450B251347C8329B66B295F740873BC891C7B54C40F8BC294823E3C2CC9BD8DED0C69EA3BAAB");
	execute("00da 0134 03 010001");

}

function putDataLoad_WRAP_DESKey() {
	show('\nPut Data : DEM_WRAP Key - DES Key');
	execute("00 DA 0114 10 7A8ADF648C8FA8F1A8C7852CDC89E640");
}

function putDataLoad_WRAP_AESKey() {
	show('\nPut Data : DEM_WRAP Key - AES Key');
	//execute("00 DA 0111 10 7A8ADF648C8FA8F1A8C7852CDC89E640");
	//execute("00 DA 0112 18 7A8ADF648C8FA8F1A8C7852CDC89E640A8C7852CDC89E640");
	execute("00 DA 0113 20 7A8ADF648C8FA8F1A8C7852CDC89E6407A8ADF648C8FA8F1A8C7852CDC89E640");
}

function putDataLoad_MAC_DESKey() {
	show('\nPut Data DES Key');
	execute("00 DA 0121 10 7A8ADF648C8FA8F1A8C7852CDC89E640");
}

function putDataLoad_MAC_AESKey() {
	show('\nPut Data AES Key');
	execute("00 DA 0122 10 7A8ADF648C8FA8F1A8C7852CDC89E640");
}

function putDataLoad_MAC_HMACKey() {
	show('\nPut Data HMAC Key');
	execute("00 DA 0123 20 6AB8855EC63C8CB3C19B7A0E14384C92F161BE5B03DF4575FEC7A757F36CC313");
}


function getRSAPublicKey(){
	show('\nGet Data : RSA Public Key Modulus');
	execute("00 CA 01 40 00 ");
	rsaPublicModulus = response;
	
	show('\nGet Data : RSA Public Key Exponent');
	execute("00 CA 01 50 00");
	rsaPublicExponent = response;
}

function getECPublicKey(){
	show('\nGet Data : EC Public Key Exponent');
	execute("00 CA 01 60 00");
	ecPublicKey = response;
}

function putGeneratedRSAPublicKey() {
	//3P Public Key
	show('\nPut Data : DEM_RSA_PUB Key - 3P Public Key (2048 bits) ...');
	var modulusLen = rsaPublicModulus.length/2;
	execute("00DA 0132" + intToHexConvert((modulusLen/2)+1) + "81" + rsaPublicModulus.substring(0,modulusLen));
	execute("00DA 0132" + intToHexConvert((modulusLen/2)+1) + "82" + rsaPublicModulus.substring(modulusLen, (modulusLen*2)));
	execute("00da 0134" + intToHexConvert(rsaPublicExponent.length/2) + rsaPublicExponent);
}

function putGeneratedECPublicKey() {
	//3P Public Key
	show('\nPut Data : DEM_EC_PUB Key - 3P Public Key...');
	show('\nPut Data ECDSA');
	execute("00 DA 0135" + intToHexConvert(ecPublicKey.length/2) + ecPublicKey);
}

function makeHASH(){
	//var data = "1122334455667788";
	//show('\nRESET MSE for HASH generation ...');
	//execute("00 22 F300 00");
	show('\nSET MSE (algorithm SHA1) for HASH generation ...');
	execute("00 22 F1 AA 03 8001 01");
	execute("00 2A 9080" + intToHexConvert(data.length/2)+data);
	
	show('\nSET MSE (algorithm SHA256) for HASH generation ...');
	execute("00 22 F1 AA 03 8001 02");
	execute("00 2A 9080" + intToHexConvert(data.length/2)+data);
	
	show('\nSET MSE (algorithm SHA384) for HASH generation ...');
	execute("00 22 F1 AA 03 8001 03");
	execute("00 2A 9080" + intToHexConvert(data.length/2)+data);
	
	show('\nSET MSE (algorithm SHA512) for HASH generation ...');
	execute("00 22 F1 AA 03 8001 04");
	execute("00 2A 9080" + intToHexConvert(data.length/2)+data);
	
	show('\nSET MSE (algorithm SHA224) for HASH generation ...');
	execute("00 22 F1 AA 03 8001 05");
	execute("00 2A 9080" + intToHexConvert(data.length/2)+data);
}

function messageAuthenticateSerivce() {
	//var data="11223344556677881122334455667788";
	//show('\nRESET MSE for ...');
	//execute("00 22 F300 00");
	
	var desLoaded =0;
	var hmacLoaded =0;
	for(algRef=1; algRef<16; algRef++){
		if(algRef==1){
			putDataLoad_MAC_AESKey();
		}else if((algRef>=2)&&(algRef<=11)&& (desLoaded==0)){
			putDataLoad_MAC_DESKey();
			desLoaded = 1;
		}else if((algRef>=12)&&(algRef<=15)&& (hmacLoaded==0)){
			putDataLoad_MAC_HMACKey();
			hmacLoaded = 1;
		}
		show("\nAlgorithm : "+intToHexConvert(algRef));
		show('\nSET MSE for MAC generation ...');
		execute("00 22 F1 B6 03 8001"+intToHexConvert(algRef));
		show('\nSign ...');
		execute("00 2A 9E9A"+intToHexConvert(data.length/2)+data);
		
		show('\nVerify ...');
		show('\nSend Signature Data ...');
		var signData = "002a00a8"+intToHexConvert((response.length/2)+1)+"20"+response;
		execute(signData);
		show('\nSend Plain Data ...');
		execute("002a00a8 "+intToHexConvert((data.length/2)+1)+"10"+data);
	}
}

function wrapUnwrap() {
	//show('\nRESET MSE for ...');
	//execute("00 22 F300 00");
	
	var aesLoaded =0;
	var desLoaded =0;
	for(algRef=1; algRef<11; algRef++){
		if((algRef>=1)&&(algRef<=2)&& (aesLoaded==0)){
			putDataLoad_WRAP_AESKey();
			aesLoaded = 1;
		}else if((algRef>=3)&&(algRef<=10)&& (desLoaded==0)){
			putDataLoad_WRAP_DESKey();
			desLoaded = 1;
		}
		show("\nAlgorithm : "+intToHexConvert(algRef));
		show('\nSET MSE for Wrap and Unwrap ...');
		execute("00 22 F1 B8 03 8001"+intToHexConvert(algRef));
		show('\nWrap ...');
		execute("00 2A 8680"+intToHexConvert(data.length/2)+data);
		
		show('\nUnrap ...');
		show('\Send cipher Data ...');
		var wrapData = "002A8086"+intToHexConvert(response.length/2)+response;
		execute(wrapData);
		show('Decipher ASCII value : '+ hex2ASCII(response));
	}
}

function digitalSignature() {
	show("\nAlgorithm : "+intToHexConvert(algRef));
	show('\nSET MSE for DS generation ...');
	execute("00 22 F1 B6 03 8001"+intToHexConvert(algRef));
	
	show('\nSign ...');
	execute("00 2A 9E9A"+intToHexConvert(data.length/2)+data);
	
	show('\nVerify ...');
	show('\nSend Signature Data ...');
	var signData = response;
	var signLen = signData.length/2;
	if(signLen>255){
		execute("002A 00A8"+intToHexConvert((signLen/2)+1)+"20" +signData.substring(0,signLen));
		execute("002A 00A8"+intToHexConvert((signLen/2)+1)+"40" +signData.substring(signLen, (signLen*2)));
	}else{
		execute("002A00A8"+intToHexConvert((signData.length/2)+1)+"20"+signData);
	}
	show('\nSend Plain Data ...');
	execute("002A 00A8 "+intToHexConvert((data.length/2)+1)+"10"+data);

}

function digitalSignatureRSA() {
	for(algRef=16; algRef<=27; algRef++){
		if(rsaKeyPairGenerate==0){
			keypairType ='01';
			generateKeyPair();
			putGeneratedRSAPublicKey();
			rsaKeyPairGenerate = 1;
		}
		show("\nAlgorithm : "+intToHexConvert(algRef));
		show('\nSET MSE for DS generation ...');
		execute("00 22 F1 B6 03 8001"+intToHexConvert(algRef));
		
		show('\nSign ...');
		execute("00 2A 9E9A"+intToHexConvert(data.length/2)+data);
		
		show('\nVerify ...');
		show('\nSend Signature Data ...');
		var signData = response;
		var signLen = signData.length/2;
		if(signLen>255){
			execute("002A 00A8"+intToHexConvert((signLen/2)+1)+"20" +signData.substring(0,signLen));
			execute("002A 00A8"+intToHexConvert((signLen/2)+1)+"40" +signData.substring(signLen, (signLen*2)));
		}else{
			execute("002A00A8"+intToHexConvert((signData.length/2)+1)+"20"+signData);
		}
		show('\nSend Plain Data ...');
		execute("002a00a8 "+intToHexConvert((data.length/2)+1)+"10"+data);
	
	}
}

function digitalSignatureEC() {
	for(algRef=28; algRef<33; algRef++){
		if(ecKeyPairGenerate==0){
			generateKeyPair();
			putGeneratedECPublicKey();
			ecKeyPairGenerate = 1;
		}
		show("\nAlgorithm : "+intToHexConvert(algRef));
		show('\nSET MSE for DS generation ...');
		execute("00 22 F1 B6 03 8001"+intToHexConvert(algRef));
		
		show('\nSign ...');
		execute("00 2A 9E9A"+intToHexConvert(data.length/2)+data);
		
		show('\nVerify ...');
		show('\nSend Signature Data ...');
		var signData = response;
		var signLen = signData.length/2;
		if(signLen>255){
			execute("002A 00A8"+intToHexConvert((signLen/2)+1)+"20" +signData.substring(0,signLen));
			execute("002A 00A8"+intToHexConvert((signLen/2)+1)+"40" +signData.substring(signLen, (signLen*2)));
		}else{
			execute("002A00A8"+intToHexConvert((signData.length/2)+1)+"20"+signData);
		}
		show('\nSend Plain Data ...');
		execute("002a00a8 "+intToHexConvert((data.length/2)+1)+"10"+data);
	
	}
}


/*
function digitalSignature() {
	//var data="1122334455667788";
	show('\nRESET MSE for Digital Signature generation ...');
	execute("00 22 F300 00");
	show('\nSET MSE for DS (ECDSA_SHA) generation ...');
	execute("00 22 F1 B6 03 8001 0B");
	show('\nSign ...');
	execute("00 2A 9E9A"+intToHexConvert(data.length/2)+data);
	
	show('\nVerify ...');
	show('\nSend Signature Data ...');
	var signData = "002a00a8"+intToHexConvert((response.length/2)+1)+"20"+response;
	execute(signData);
	show('\nSend Plain Data ...');
	execute("002a00a8 "+intToHexConvert((data.length/2)+1)+"10"+data);
}
*/


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
	for(i = 0; i<inputStr.length; i+=1)
		str += inputStr.charCodeAt(i).toString(16);
	return str.toUpperCase();
}