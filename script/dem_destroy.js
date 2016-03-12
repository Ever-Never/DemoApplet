demScript = new ShellScript();
mainProcedure();


var response;


function execute(command) {
	response = demScript.send(command);
//	demScript.assertSW('9000');
}

function show(show) {
	demScript.print(show);
}

function mainProcedure() {
	destroy();
}

function destroy() {
	show('\n\n****************************** Destroy Service : START ******************************');
	execute("00 DA 01 FF 00");
	show('****************************** Destroy Service : END ******************************');
}