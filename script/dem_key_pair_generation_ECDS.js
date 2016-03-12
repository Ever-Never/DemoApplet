demScript = new ShellScript();
mainProcedure();


function mainProcedure() {
	keyPairGeneration();
}

function keyPairGeneration() {
//	show('\nGenerating RSA 2048-bit Key-Pair for Sign/Verify...');
//	execute("00 46 00 00 01 01");
//	
//	show('\nGenerating RSA 2048-bit Key-Pair for Wrap/Unwrap...');
//	execute("00 46 00 00 01 03");
	
	show('\nGenerating EC P-521 Key-Pair for Sign/Verify...');
	execute("00 46 00 00 01 15");
}

function show(show) {
	demScript.print(show);
}

function execute(command) {
	response = demScript.send(command);
//	demScript.assertSW('9000');
}