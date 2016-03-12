demScript = new ShellScript();
mainProcedure();


function mainProcedure() {
	show('\nRESET MSE ...');
	execute("00 22 F300 00");
	show('\nSetting MSE with Cipher(Confidentiality) algorithm: ALG_AES_CBC_PKCS5');
	execute("00 22 F1 B8 03 8001 04");
	
	randGeneration();
}

function randGeneration() {
//	show('\nGenerating 16 byte Random Number without seed...');
//	execute("00 84 00 00 02 1010");
//	
	show('\nInit Random Object with 16 bytes seed. original seed value: 1122334455667788112233445566778811223344556677881122334455667788');
	execute("00 84 00 00 31 10 8D9AEFECDD8C3291376F8344DB1BFA98EDAABC4952015CCCBF5A9E9C4B4C7EB11DAB2A5473CA8449FB33BDD8DA187ECF");
	
	show('\nGenerating 16 byte Random ...');
	var n = 5;
	for(i = 0; i<n; i++) {
		execute("00 84 00 00 02 3010");
	}
	
	show('\nClear Random Object ...');
	execute("00 84 00 00 01 40");
}

function show(show) {
	demScript.print(show);
}

function execute(command) {
	response = demScript.send(command);
//	demScript.assertSW('9000');
}