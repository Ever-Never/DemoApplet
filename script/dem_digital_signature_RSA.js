demScript = new ShellScript();
mainProcedure();

var mod;
var exp;
var data;
var response;
var keypairType;
var ecPublicKey;
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
	show('\n\nTo do Sign and Verify, we need RSA key-pair, signing Algorithm and Plain Text.\n'
		+'It is recommended that to invoke this service, invoke Key Pair Generation Service first!...\n'
		+'We will do the following steps...\n '
		+'1. Restore MSE\n'
		+'2. SET MSE with Signature Algorithm: ALG_RSA_SHA_512_PKCS1\n'
		+'3. GET the Public Key \n'
		+'4. Put the Public Key into DEM-3P-PUB-KEY container\n'
		+'5. Do Sign and Verify');
	var plainText='Kona Software Lab Limited, Dhaka';
	data = ascii2Hex(plainText);
	show('\nPlain Text is : '+ plainText);
	show('Plain Text in Hex : '+ data);
	
	show('\nRESTOREing MSE...');
	restoreMSE();
	
	/********	RSA Sign generation and verification STARTs	********/
	show('\nSETing MSE with Signature Algorithm: ALG_RSA_SHA_512_PKCS1');
	execute("00 22 F1 B6 03 8001 1B");
	
	mod = '21';
	exp = '22';
	
	show('\Getting Generated RSA Public-key...');
	getRSAPublicKey();	
	show('\nPutting Generated RSA Public-key into DEM-3P-PUB key container...');
	putGeneratedRSAPublicKey();
	digitalSignatureRSA();
	/********	RSA Sign generation and verification ENDs	********/
}

function restoreMSE() {
	show('\nRESET MSE ...');
	execute("00 22 F300 00");
}

function getRSAPublicKey(){
	show('\nGet Data : RSA Public Key Modulus...');
	execute("00 CA 01"+ mod+ "00");
	rsaPublicModulus = response;
	
	show('\nGet Data : RSA Public Key Exponent...');
	execute("00 CA 01"+ exp + "00");
	rsaPublicExponent = response;
}


function putGeneratedRSAPublicKey() {
	var modulusLen = rsaPublicModulus.length/2;
	execute("00DA 0132" + intToHexConvert((modulusLen/2)+1) + "81" + rsaPublicModulus.substring(0,modulusLen));

	execute("00DA 0132" + intToHexConvert((modulusLen/2)+1) + "82" + rsaPublicModulus.substring(modulusLen, (modulusLen*2)));

	execute("00da 0134" + intToHexConvert(rsaPublicExponent.length/2) + rsaPublicExponent);
}

function digitalSignatureRSA() {
	show('\nSign ...');
	execute("00 2A 9E9A"+intToHexConvert(data.length/2)+data);		
	show('\nVerify starts: ');
	show('Send Signature Data ...');
	var signData = response;
	var signLen = signData.length/2;
	if(signLen>255){
		execute("002A 00A8"+intToHexConvert((signLen/2)+1)+"20" +signData.substring(0,signLen));
		execute("002A 00A8"+intToHexConvert((signLen/2)+1)+"40" +signData.substring(signLen, (signLen*2)));
	}else{
		execute("002A00A8"+intToHexConvert((signData.length/2)+1)+"20"+signData);
	}
	show('Send Plain Data and Verify ...');
	execute("002a00a8 "+intToHexConvert((data.length/2)+1)+"10"+data);
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