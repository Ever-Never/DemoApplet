demScript = new ShellScript();
mainProcedure();


function mainProcedure() {
	show('\nIn this service, it is assumed that all the incoming key are wrapped/encrypted with either AES-256 Secret key or RSA-2048 Public key.\n'
			+'DEM-WRAP-SECRET container has preloaded (if not changed yet) AES-256 key with key values:.\n'
			+'404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F.\n'
			+'This key can be used to update all of the containers but here only DEM-WRAP-SECRET, DEM_Auth and DEM_MAC key containers will be updated by this key.\n'
			+'DEM-CON-SECRET key container  will be updated by RSA-2048 key.\n'
			+'We will do the following steps...\n '
			+'1. Restore MSE.\n'
			+'2. Set MSE with Cipher(Confidentiality) algorithm: ALG_AES_CBC_PKCS5\n'
			+'3. Put data into DEM-WRAP-SECRET, DEM_Auth and DEM_MAC key containers\n'
			+'4. Asuming that DEM-WRAP-PRI container is updated with RSA-2048 private key by invoking Key Pair Generation Service,'
			+'Set MSE with Cipher(Confidentiality) algorithm: ALG_RSA_PKCS1\n'
			+'5. Put data into DEM-CON-SECRET key container\n'
			);
	restoreMSE();
	
	show('\nSetting MSE with Cipher(Confidentiality) algorithm: ALG_AES_CBC_PKCS5');
	execute("00 22 F1 B8 03 8001 04");
	putDataUsingSecKey();

	show('\nSetting MSE with Cipher(Confidentiality) algorithm: ALG_RSA_NOPAD');
	execute("00 22 F1 B8 03 8001 11");
	putDataUsingAsymKey();
}

function putDataUsingSecKey() {
	show('\n\n****************************** UPDATE DEMO KEY SERVICE : START ******************************');
	
	//WRAP Key
	show('\nPut Data : DEM-WRAP-SECRET Key - AES-256 Key. Original key value: 404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F');
	execute("00 DA 01 41 30 C9302AFCA51094FD928A36794A628B81F8E8DDE7CBC0F313564B9A3312AE48FD334C8EB24B43A89512B206CD9869CC74");
	
	//Auth Key
	show('\nPut Data : DEM_Auth Key - AES-128 Key. Original key value: 404142434445464748494A4B4C4D4E4F');
	execute("00 DA 01 01 20 C9302AFCA51094FD928A36794A628B81461BDFFBC1FD8ADEF74750281A92EF92");	
	
	
	//MAC Key
	show('\nPut Data : DEM_MAC Key - AES-256 Key. Original key value: 1122334455667788112233445566778811223344556677881122334455667788');
	execute("00 DA 01 24 30 8D9AEFECDD8C3291376F8344DB1BFA98EDAABC4952015CCCBF5A9E9C4B4C7EB11DAB2A5473CA8449FB33BDD8DA187ECF");

//	show('\nPut Data HMAC Key. Original key value: A1A2A3A4A5A6A7A8A1A2A3A4A5A6A7A8A1A2A3A4A5A6A7A8A1A2A3A4A5A6A7A8');
//	execute("00 DA 01 25 30 466B621657C5D5290669E4AA47A644E37A1F3CD2DD613F1657E3F8769ECC793ACA2B2692C9D0E7B18BBC76B6A792D898");
	
	show('****************************** UPDATE DEMO KEY SERVICE : END ******************************');
}

function putDataUsingAsymKey() {
	show('\n\n****************************** UPDATE DEMO KEY SERVICE : START ******************************');
	
	//CON Key
	show('\nPut Data : DEM-CON-SECRET Key - DES-128 Key. Original key value: 404142434445464748494A4B4C4D4E4F');
	
	execute("00 DA 01 14 80 883C6C35F742045D629A441943F0FD2C6117DC46344374A6598AF06CAB83EB863D11D09392142D6F8A1F2746527FC80E8CEAED0C0568826DA6A8B9B50D0E601555222ED81D0F882C2E814397143D6876113CFB534256BCB7D99E30A108CD274D53E0E0D9482F5591566C122E4E726734DBAC57266EFE3A0F870CCBF7D9DD36EB");
	
	execute("00 DA 01 14 80 C4AD2FFBF1BD371F889437633342E76C1DDD208DD03FDFD74626DD1B4B885B7B4BD5231BA5DA267C32ED60E4F8567CC185D4403E9FE740E946D3B541E12A0F3B92C345A3A893F7E00DC1C1596973365C9DD17C457A7BBA7DD60CD21B2DB94724EE622803791F3E698991DFE58A6337FE4256E489B716F887EDACE7C2704A4628");
	
	show('****************************** UPDATE DEMO KEY SERVICE : END ******************************');
}

function restoreMSE() {
	show('\nRESET MSE ...');
	execute("00 22 F300 00");
}

function show(show) {
	demScript.print(show);
}

function execute(command) {
	response = demScript.send(command);
//	demScript.assertSW('9000');
}