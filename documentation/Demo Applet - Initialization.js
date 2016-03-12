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
function execute(command) {
	response = konaScript.send(command);
	konaScript.assertSW('9000');
}

function show(show) {
	konaScript.print(show);
}

function mainProcedure() {
	//deleteApplet();
	//loadApplet();
	installApplet();
/*	
	show('\nWelcome to DemoApplet....');
	selectApplet();
	secureChannel();
	putDataLoadKey();
	selectISD();
	secureChannel();
	freeMemory();
*/
}

function deleteApplet() {
	freeMemory();
	show('\nDeleting DemoApplet...');
	execute("80E4 0000 0D 4F 0B 6B6F6E61736C6669707300");
	freeMemory();
	execute('80E4 0000 0C 4F 0A 6B6F6E61736C66697073');
	freeMemory();
}
	
function loadApplet() {
	freeMemory();
	show('\nLoading DemoApplet...');
	konaScript.loadCAP('D:\\Development\\workspaceJCOP\\fips-demo-applet\\bin\\com\\konasl\\demoapplet\\javacard\\demoapplet.cap');
	//execute("80E60200170A6B6F6E61736C6669707308A00000015100000000000000");
	freeMemory();
}

function installApplet() {
	freeMemory();
	show('\nInstalling DamoApplet...');
	execute('80E6 0C00 29 0A 6B6F6E61736C66697073 0B 6B6F6E61736C6669707330 0B 6B6F6E61736C6669707300 010002C900 00');
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
	konaScript.auth();
}

function freeMemory(){
	show("\nThe available E2P size......")
	execute("B002000000");
	show("Free Memory : "+response.substring(8,12));
}

function putDataLoadKey() {
	show("CSP Initialization ...");
	show('\nPut Data DES Key');
	execute("00 DA 0121 10 7A8ADF648C8FA8F1A8C7852CDC89E640");
	
	show('\nPut Data AES Key');
	execute("00 DA 0122 10 7A8ADF648C8FA8F1A8C7852CDC89E640");

	show('\nPut Data HMAC Key');
	execute("00 DA 0123 20 6AB8855EC63C8CB3C19B7A0E14384C92F161BE5B03DF4575FEC7A757F36CC313");
	
	show('\nPut 3P Public Key ...');
	execute("00da 0132 81 81 9CBDC33F870F25F5BCFCA50890F0296B584A338AE2BB3EDE567F2F4620AA46BF5F3080133EBD8A2357E01A4783E40EC0ABF1D51A6D31713E6DDB79DC3638AF5A5B08C2DB18EDEBFB15EE2A1A6BC3E895CFA1E2601CAB0CC284E44A8C182C1298AF21A9286AFBA4EF3C89FEE87ECC3D1A1C0A74E5B6AD7E13BBA5B625721E4B89");
	execute("00da 0132 81 82 18E785C2E41A5E2B323919E7F23FD25232EAAFDCBAA807191E95C7DEDF0F9E824EECBAC42E58E1992308396BC888C92CA3A8188526AA32B401B2DC64BE8D0CDFBD2797ED8BABF8196B34EFFE6B6C400444534D3228FE6C2E5C5A450B251347C8329B66B295F740873BC891C7B54C40F8BC294823E3C2CC9BD8DED0C69EA3BAAB");
	execute("00da 0134 03 010001");
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
	for(i = 0; i<inputStr.length; i+=1)
		str += inputStr.charCodeAt(i).toString(16);
	return str.toUpperCase();
}