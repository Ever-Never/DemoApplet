demScript = new ShellScript();
mainProcedure();


function mainProcedure() {
	show('\nIn this service, all the outgoing keys are wrapped/encrypted with either AES-256 Secret key or RSA-2048 Public key.\n'
			+'DEM-WRAP-SECRET container has preloaded (if not changed yet) AES-256 key with key values:.\n'
			+'404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F.\n'
			+'This key will can be used to Wrap the outgoing keys: DEM-WRAP-SECRET, DEM_Auth and DEM_MAC keys.\n'
			+'DEM-CON-SECRET key container  will be wrapped by RSA-2048 key.\n'
			+'We will do the following steps...\n '
			+'1. Restore MSE.\n'
			+'2. Set MSE with Cipher(Confidentiality) algorithm: ALG_AES_CBC_PKCS5\n'
			+'3. Get data from DEM-WRAP-SECRET, DEM_Auth and DEM_MAC key containers\n'
			+'4. Asuming that DEM-3P-PUB key container is updated with RSA-2048 Public key by invoking Update Demo Key Service,'
			+'Set MSE with Cipher(Confidentiality) algorithm: ALG_RSA_PKCS1\n'
			+'5. Get data into DEM-CON-SECRET key container\n'
			);
	restoreMSE();
	
	show('\nSetting MSE with Cipher(Confidentiality) algorithm: ALG_AES_CBC_PKCS5');
	execute("00 22 F1 B8 03 8001 04");
	getKeyUsingSecKey();
	
	
	show('\nSetting MSE with Cipher(Confidentiality) algorithm: ALG_RSA_NOPAD');
	execute("00 22 F1 B8 03 8001 12");
	getKeyUsingAsyKey();
}

function restoreMSE() {
	show('\nRESET MSE ...');
	execute("00 22 F300 00");
}

function getKeyUsingSecKey() {
	
	show('\nRetriving DEM-WRAP-SECRET key...');
	execute("00 CA 01 40 00");
	
	show('\nRetriving DEM_AUTH key...');
	execute("00 CA 01 01 00");
	
	show('\nRetriving DEM_MAC key...');
	execute("00 CA 01 20 00");
}

function getKeyUsingAsyKey() {
	
	show('\nRetriving DEM-CON-SECRET key...');
	execute("00 CA 01 10 00");
}

function show(show) {
	demScript.print(show);
}

function execute(command) {
	response = demScript.send(command);
//	demScript.assertSW('9000');
}