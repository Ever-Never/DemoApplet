demScript = new ShellScript();
mainProcedure();


function mainProcedure() {
	show("\nSending External Authenticate(fail) Command...");
	
	externalAuthenticate();
}

function externalAuthenticate() {
	execute('84 82 0000 10 00000000000000000000000000000000');	
}

function show(show) {
	demScript.print(show);
}

function execute(command) {
	response = demScript.send(command);
//	demScript.assertSW('9000');
}
