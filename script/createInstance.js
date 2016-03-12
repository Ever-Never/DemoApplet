{
	konaScript = new ShellScript();
	konaScript.reset();
	konaScript.select('A000000151000000');
	konaScript.auth();
	mainProcedure();
}
function execute(command) {
	response = konaScript.send(command);
//	konaScript.assertSW('9000');
}

function show(show) {
	konaScript.print(show);
}

function mainProcedure() {
	installApplet();
}


function installApplet() {
	show('\nInstalling DamoApplet...');
	execute('80E6 0C00 29 0A 6B6F6E61736C66697073 0B 6B6F6E61736C6669707330 0B 6B6F6E61736C6669707300 010002C900 00');
}
