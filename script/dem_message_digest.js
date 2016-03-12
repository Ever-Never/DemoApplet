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
	show('\n\nTo Generate Message Digest, HASH Algorithm and Plain Text.\n'
		+'We will do the following steps...\n '
		+'1. Restore MSE first\n'
		+'2. SET MSE with HASH Algorithm: ALG_SHA_256 \n'
		+'3. Generate Message Digest\n');
	var plainText='Kona Software Lab Limited, Dhaka';
	data = ascii2Hex(plainText);
	show('\nPlain Text is: '+ plainText);
	show('Plain Text in Hex : '+ data);
	
	show('\nRESTOREing MSE...');
	restoreMSE();
	
	show('\nSETing MSE with HASH Algorithm: ALG_SHA_256');
	execute("00 22 F1 AA 03 8001 03");
	
	messageDigest();
	
}

function restoreMSE() {
	show('\nRESET MSE ...');
	execute("00 22 F300 00");
}

function messageDigest(){
	show('\n\n****************************** MESSAGE DIGEST SERVICE: START ******************************');
	show('\nGenerating MESSAGE DIGEST...');
		execute("00 2A 9080" + intToHexConvert(data.length/2)+data);
	show('****************************** MESSAGE DIGEST SERVICE: END ******************************');
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