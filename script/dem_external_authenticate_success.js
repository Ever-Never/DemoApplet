demScript = new ShellScript();
mainProcedure();


function mainProcedure() {
	show("\nSending External Authenticate Command...");
	externalAuthenticate();
}

function externalAuthenticate() {
	execute('84 82 0000 10 11C38AD04CC78565E46C3B7318E4E521');	
}

function show(show) {
	demScript.print(show);
}

function execute(command) {
	response = demScript.send(command);
//	demScript.assertSW('9000');
}
