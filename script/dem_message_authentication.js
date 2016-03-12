demScript = new ShellScript();
mainProcedure();


var data;
var response;


function execute(command) {
	response = demScript.send(command);
//	demScript.assertSW('9000');
}

function show(show) {
	demScript.print(show);
}

function mainProcedure() {
	show('\n\nFor Message Authentication, we need MAC key, MAC Algorithm and Plain Text.\n'
		+'We will do the following steps...\n '
		+'1. Restore MSE with MAC algo ALG_AES_MAC_128_NOPAD\n'
		+'2. Put AES-128 MAC key into key container\n'
		+'3. Generate MAC and Verify\n');
	var plainText='Kona Software Lab Limited, Dhaka';
	data = ascii2Hex(plainText);
	show('\nPlain Text is : '+ plainText);
	show('Plain Text in Hex : '+ data);
	
	show('\nRESTOREing MSE...');
	restoreMSE();
	
	putMACkey();
	
	messageAuthenticateSerivce();
}

function restoreMSE() {
	show('\nRESET MSE ...');
	execute("00 22 F300 00");
}

function putMACkey() {
	show('\nPut Data AES-127 MAC  Key');
	execute("00 DA 01 22 20 7A8ADF648C8FA8F1A8C7852CDC89E6407A8ADF648C8FA8F1A8C7852CDC89E640");
}

function messageAuthenticateSerivce() {
	show('\n\n****************************** MESSAGE AUTHENTICATION SERVICE: START ******************************');
	show('\nGenerating MAC ...');
	execute("00 2A 9E9A"+intToHexConvert(data.length/2)+data);
	
	show('\nVerifying MAC...');
	show('\nSend Generated MAC...');
	var signData = "002a00a8"+intToHexConvert((response.length/2)+1)+"20"+response;
	execute(signData);
	show('\nSend Plain Data and Verify...');
	execute("002a00a8 "+intToHexConvert((data.length/2)+1)+"10"+data);
	show('****************************** MESSAGE AUTHENTICATION SERVICE: END ******************************');
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