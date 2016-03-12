demScript = new ShellScript();
mainProcedure();


function mainProcedure() {
	show('\nSetting MSE with Cipher(Confidentiality) algorithm: ALG_AES_CBC_PKCS5');
	execute("00 22 F1 B8 03 8001 04");
	getSharedSecret();
}

function getSharedSecret() {
	show('\nRetriving Shared Secret...');
	execute("00 CA 01 30 00");
}

function show(show) {
	demScript.print(show);
}

function execute(command) {
	response = demScript.send(command);
//	demScript.assertSW('9000');
}