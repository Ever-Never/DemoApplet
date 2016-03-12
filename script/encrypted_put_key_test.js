demScript = new ShellScript();
mainProcedure();

var mod;
var exp;
var wrapData;
var response;
var K;
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
	show('\n\nSuppose we have a pre-calculated AES-128 Session key K1(11223344556677881122334455667788) which is pre-loaded into wrap-key container!'
			+'We use this AES-128 key K1 and algorithm: ALG_AES_BLOCK_128_CBC_NOPAD for Wrap/Unwrap\n'
			+'We will do the following steps...\n '
			+'1.Encrypt a tested key K(A1A2A3A4A5A6A7A8A1A2A3A4A5A6A7A8) with key K1 and algorithm: ALG_AES_BLOCK_128_CBC_NOPAD \n'
			+'2. Put This encrypted Key into WRAP key container\n'
			+'3. Generate ENCRYPTION MESSAGE of a plain text(ABABABABABABABABABABABABABABABAB) C with Key Wrap Services!\n');
	
	K='A1A2A3A4A5A6A7A8A1A2A3A4A5A6A7A8';
	show('\nTested key K is : '+ K);
	
	show('\nRESTOREing MSE...');
	restoreMSE();
	
	show('\nWraping key K...\n');
	symmetricWrapUnwrap();
	show('\Putting encrypted value of key K...');
	putWrapKey();
	
	show('Generating ENCRYPTION MESSAGE of a plain text(ABABABABABABABABABABABABABABABAB) C with Key Wrap Services!\n');
	K='ABABABABABABABABABABABABABABABAB';
	symmetricWrapUnwrap();
	
	show('\nNow using algorithm: ALG_AES_BLOCK_128_CBC_NOPAD and Key K, generate ENCRYPTION MESSAGE of a plain text(ABABABABABABABABABABABABABABABAB) C outside of the card\n'
			+'Match this two Cs!!!\n'
			+'NOTE: The base Wrap key is changed now! Use Destroy service to recover the pre-loaded base key!\n');
}

function restoreMSE() {
	show('\nRESET MSE ...');
	execute("00 22 F300 00");
}

function putWrapKey() {
	show('\nPut Data : DEM_WRAP Key container');
	execute("00 DA 01 11"+intToHexConvert(wrapData.length/2) + wrapData);
}


function symmetricWrapUnwrap() {
	execute("00 2A 8680"+intToHexConvert(K.length/2 +1) + "40" + K);
	
	wrapData = response;
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