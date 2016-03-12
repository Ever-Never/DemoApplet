demScript = new ShellScript();
mainProcedure();


function mainProcedure() {
	getPublicKey();
}

function getPublicKey() {
	show('\nRetriving RSA_PUB_KEY_MOD_SIGN...');
	execute("00 CA 01 21 00");
	
	show('\nRetriving RSA_PUB_KEY_EXP_SIGN...');
	execute("00 CA 01 22 00");
	
	show('\nRetriving RSA_PUB_KEY_MOD_CON...');
	execute("00 CA 01 11 00");
	
	show('\nRetriving RSA_PUB_KEY_EXP_CON...');
	execute("00 CA 01 12 00");
	
	show('\nRetriving EC_PUB_KEY...');
	execute("00 CA 01 23 00");
}

function show(show) {
	demScript.print(show);
}

function execute(command) {
	response = demScript.send(command);
//	demScript.assertSW('9000');
}