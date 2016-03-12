demScript = new ShellScript();
mainProcedure();


function mainProcedure() {
	getAppletInfo();
}

function getAppletInfo() {
	show('\nRetriving Applet Info...');
	execute("00 CA 01 90 00");
}

function show(show) {
	demScript.print(show);
}

function execute(command) {
	response = demScript.send(command);
//	demScript.assertSW('9000');
}