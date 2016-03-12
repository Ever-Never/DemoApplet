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
	show('\n\nFor Bulk Data Enc/Dec Symmetric Key encryption techniques will be used.'
		+'We need DES/AES key for Confidentiality(key wrap) operation,'
		+'encryption Algorithm and Plain Text.\n'
		+'We will do the following steps...\n '
		+'1. Restore MSE\n'
		+'2. Set MSE with Cipher(Confidentiality) algorithm: ALG_DES_CBC_PKCS5\n'
		+'3. Do Enc/Dec!'
		);
	
	plainText='Kona Software Lab Limited, Dhaka';
	data = ascii2Hex(plainText);
	show('\nPlain Text is : '+ plainText);
	show('Plain Text in Hex : '+ data);
	
	show('\nRESTOREing MSE...');
	restoreMSE();
	
	show('\nSetting MSE with Cipher(Confidentiality) algorithm: ALG_DES_CBC_PKCS5');
	execute("00 22 F1 B8 03 8001 0C");
	symmetricEncDec();
}

function restoreMSE() {
	show('\nRESET MSE ...');
	execute("00 22 F300 00");
}

function symmetricEncDec() {
	show('****************************** SYMMETRIC KEY CON SERVICE: STARTs ******************************');
	show('\nPlain Text is :' + plainText);
	show('\nENC ...');
	execute("00 2A 8680"+intToHexConvert(data.length/2) + data);
	
	show('\nDEC ...');
	show('Send cipher Data ...');
	var wrapData = "00 2A 8086"+ intToHexConvert(response.length/2) + response;
	execute(wrapData);
	show('Decipher ASCII/Plain value : '+ hex2ASCII(response));
	show('******************************SYMMETRIC KEY CON SERVICE: END ******************************');
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