demScript = new ShellScript();
mainProcedure();


function mainProcedure() {
	show("\nSending Initialize Update Command...");
	initializeUpdate();
}

function initializeUpdate() {
	execute('80 50 0000 08 A1A2A3A4A5A6A7A8');	
}

function show(show) {
	demScript.print(show);
}

function execute(command) {
	response = demScript.send(command);
//	demScript.assertSW('9000');
}