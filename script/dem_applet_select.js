demScript = new ShellScript();
mainProcedure();


function mainProcedure() {
	show("\nSelecting Demo-Applet...");
	selectDemoApplet();
}

function selectDemoApplet() {
	execute('00 A4 0400 0B 6B6F6E61736C6669707300');
}

function show(show) {
	demScript.print(show);
}

function execute(command) {
	response = demScript.send(command);
}
