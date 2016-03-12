demScript = new ShellScript();
mainProcedure();


function mainProcedure() {
	show('\nIn this service, it is assumed that all the incoming key are wrapped/encrypted with either AES-256 Secret key or RSA-2048 Public key.\n'
			+'DEM-WRAP-SECRET container has preloaded (if not changed yet) AES-256 key with key values:.\n'
			+'404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F.\n'
			+'This key will can be used to update all of the containers but here only DEM-WRAP-SECRET, DEM_Auth and DEM_MAC key containers will be updated by this key.\n'
			+'DEM-CON-SECRET key container  will be updated by RSA-2048 key.\n'
			+'We will do the following steps...\n '
			+'1. Restore MSE.\n'
			+'2. Set MSE with Cipher(Confidentiality) algorithm: ALG_AES_CBC_PKCS5\n'
			+'3. Put data into DEM-WRAP-SECRET, DEM_Auth and DEM_MAC key containers\n'
			+'4. Asuming that DEM-WRAP-PRI container is updated with RSA-2048 private key by invoking Key Pair Generation Service,'
			+'Set MSE with Cipher(Confidentiality) algorithm: ALG_RSA_NOPAD\n'
			+'5. Put data into DEM-CON-SECRET key container\n'
			);
	
	putData3PPubKey();
}

function putData3PPubKey() {
	show('\n\n****************************** UPDATE DEMO 3P Public KEY SERVICE : START ******************************');
	
	show('\nPut Data : DEM_RSA_PUB Key - 3P Public Key (2048 bits) ...');
	execute("00da 0132 81 81 BDF3E5B191854430F395742C3C8E0A93EBCF820E669C4EF6EC2BF004AECC732BC307CA4432D698580963A53B66E26028E9C6C0AF9E7440B6562001E7E50F6B6DAA376715831DCD5DD5D5A82F9A36A9E5C53242C629B157B657A71FE503DAB28EC8467CE9C0C12C65E3497984EF5DD1520534CDCF9E191F35D71EF5DDB4B7A3FD");

	execute("00da 0132 81 82 EAE457A8979FC3755A5A9AF47BA12905BECBE688829C925B76163B4DC96884061A95FD57C5581298C9E8B7590806DD4B45E985AEE48090570D472DD6E03228C4CE522D5277E35BFD289960DE791EE66A7233EEE92B31094A243B5C2BFC4A86CD6E013CE5B17BE042FDACF9D7271C390DE3F4774E8ECD8134784BB365CB3CA005");
	
	execute("00da 0134 03 010001");
	
	show('****************************** UPDATE DEMO 3P Public KEY SERVICE : END ******************************');
}

function show(show) {
	demScript.print(show);
}

function execute(command) {
	response = demScript.send(command);
//	demScript.assertSW('9000');
}