demScript = new ShellScript();
mainProcedure();


var response;


function execute(command) {
	response = demScript.send(command);
	demScript.assertSW('9000');
}

function show(show) {
	demScript.print(show);
}

function mainProcedure() {
	show('\n\nFor Key Agreement we need a valid EC Public Key. Demo-Applet supports only one Key Agreement Algorithm: ALG_ECSVDP_DH'
			+'\nWe use a valid Third Party EC-521 Public Key for Key Agreement');
	show('\nRESET MSE ...');
	execute("00 22 F300 00");
	keyAgreement();
}

function keyAgreement() {
	show('\n\n****************************** Key Agreement Service : START ******************************');
//	var ec_521 = "04012D58C262FD7AA3BCFA1330C2174B0BD568DE8685057E7ECCBC25D3A1643B9BBADA1C4A5D094216E5EED5E54649E9850EA38F467BCF8DFC5056A71B907B33087BB60106F507451B7E14CF6725DF7D53039658ED8046D5CC09C29CD4E3EA4BB1611EFF20FC7CBF7A858C48FCE1C55D5FFA14D91BA11085BC16F6F02509FE3C7E21AD192D";
	var ec_521 = "040148EEB5DCC73185C8FF012C8B911780FCCB8484D8FCDCD41FCB4CFF34559668AB9D1F8CDEBC2B5715EE6BC8B3B883326883D3CBB2D93914A1335C2AF7CA3AC4A3FD001186C7A19B0C64EEAEA81BF874DDB0987BF3FDC9CF68EB1286F60CA25ACA7B5FC11064295B037D061822856F9325CAB317E12866E87F353FC34E1D17264E24C689";
	apdu = "0086" + "15" + "00" +  intToHexConvert(ec_521.length/2)+ ec_521;
	execute(apdu);	
	show('****************************** Key Agreement Service : END ******************************');
}

function intToHexConvert(integer){
	var str = integer.toString(16);
	return str.length ==1? "0"+str : str;
}