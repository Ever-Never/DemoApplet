/*
 * DemoApplet
 * Date Created: Mar 31, 2014
 * Release Date: December 05, 2014
 * Version: 1.2.1
 */
package com.konasl.demoapplet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.HMACKey;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.PrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class DemoApplet extends Applet implements AppletEvent{
	static final byte APP_STATUS_INSTALLED			= (byte)0x01;
	static final byte APP_STATUS_INITIALIZED		= (byte)0x02;
	static final byte APP_STATUS_PERSONALIZED		= (byte)0x03;
	static final byte APP_STATUS_BLOCKED			= (byte)0x04;
	static final byte APP_STATUS_DEAD				= (byte)0x05;
	
	//PIN offset
	static final byte OFFSET_PIN_USER				= (byte)0x00;
	static final byte OFFSET_PIN_SO					= (byte)0x01;
	
	//CSP offset
	static final byte OFFSET_CSP_DEM_AUTH   		= (byte)0x00;
	static final byte OFFSET_CSP_DEM_MAC			= (byte)0x01;
	static final byte OFFSET_CSP_DEM_CON_SECRET   	= (byte)0x02;
	static final byte OFFSET_CSP_DEM_3P_PUB   		= (byte)0x03;
	static final byte OFFSET_CSP_DEM_KEY_WRAP   	= (byte)0x04;
	
	//KEY offset
	static final byte OFFSET_KEY_DES				= (byte)0x00;
	static final byte OFFSET_KEY_AES				= (byte)0x01;
	static final byte OFFSET_KEYPAIR_DS				= (byte)0x02;
//	static final byte OFFSET_KEYPAIR_RSA			= (byte)0x02;
//	static final byte OFFSET_KEYPAIR_ECC			= (byte)0x03;
	static final byte OFFSET_KEY_HMAC				= (byte)0x04;
	static final byte OFFSET_KEYPAIR_3P				= (byte)0x05;
	static final byte OFFSET_KEYPAIR_RSA_WRAP		= (byte)0x06;
	
	//Random offset
	static final byte OFFSET_SECURE_RANDOM			= (byte)0x00;
	static final byte OFFSET_PSEUDO_RANDOM			= (byte)0x01;
	
	//Cipher offset
	static final byte OFFSET_CIPHER_DES_CBC			= (byte)0x00;
	static final byte OFFSET_CIPHER_DES_ECB			= (byte)0x01;
	static final byte OFFSET_CIPHER_AES_CBC			= (byte)0x02;
	static final byte OFFSET_CIPHER_AES_ECB			= (byte)0x03;
	static final byte OFFSET_CIPHER_SCP02_DES_CBC	= (byte)0x04;
	static final byte OFFSET_CIPHER_RSA				= (byte)0x05;

	//Digest offset
	static final byte OFFSET_DIGEST_SHA1			= (byte)0x00;
	static final byte OFFSET_DIGEST_SHA2			= (byte)0x01;
	
	//Signature offset
	static final byte OFFSET_SIGN_MAC_AES   		= (byte)0x00;
	static final byte OFFSET_SIGN_MAC_3DES   		= (byte)0x01;
	static final byte OFFSET_SIGN_MAC_HMAC   		= (byte)0x02;
	static final byte OFFSET_SIGN_RSA		   		= (byte)0x03;
	static final byte OFFSET_SIGN_EC   				= (byte)0x04;
	
	//flag offset
	static final byte OFFSET_PUT_FIRST_PART			= (byte)0x00;
	static final byte OFFSET_1024_MODULUS_CHECKED	= (byte)0x01;
	static final byte OFFSET_2048_MODULUS_CHECKED	= (byte)0x02;
	static final byte OFFSET_SIGN_DATA_CHECK		= (byte)0x03;
	static final byte OFFSET_SIGN_VERIFY_CHECK		= (byte)0x04;
	
	
	
	//Operation offset
	static final byte OFFSET_MSE					= (byte)0x00;
	static final byte OFFSET_STATE					= (byte)0x01;
	
	//MSE offset
	static final byte OFFSET_SE_DSA					= (byte)0x00;
	static final byte OFFSET_SE_HASH				= (byte)0X01; 
	static final byte OFFSET_SE_CON					= (byte)0X02;
	static final byte OFFSET_VERIFY_DS				= (byte)0x03;
	
	//Class
	static final byte CLA_NO_SM						= (byte)0x00;
	static final byte CLA_SM						= (byte)0x80;
	
	//Instruction
	static final byte INS_GET_DATA 					= (byte)0xCA;
	static final byte INS_PUT_DATA					= (byte)0xDA;
	static final byte INS_PSO						= (byte)0x2A;
	static final byte INS_GET_CHALLANGE				= (byte)0x84;
	static final byte INS_MSE						= (byte)0x22; 
	static final byte INS_GENERATE_KEY_PAIR			= (byte)0x46;
	static final byte INS_INITIALIZE_UPDATE			= (byte)0x50;
	static final byte INS_EXTERNAL_AUTHENTICATION 	= (byte)0x82;
	static final byte INS_GENERAL_AUTHENTICATION 	= (byte)0x86;

	static final byte INS_SELECT_APPLET				= (byte)0xA4;
	
	//Put Data type 
	static final byte DEMO_KEYS						= (byte)0x00;
	static final byte DEMO_KEYS_DESTROY				= (byte)0x80;

	//key checking
	static final byte AUTH_KEY						= (byte)0x00;
	static final byte CON_KEY						= (byte)0x10;
	static final byte MAC_KEY						= (byte)0x20;
	static final byte PUB_KEY						= (byte)0x30;
	static final byte WRAP_KEY						= (byte)0x40;
	
	//get data
	static final byte GET_OPERATION_STATE			= (byte)0x00;
	static final byte GET_SECRET_KEY_AUTH			= (byte)0x01;
	static final byte GET_SECRET_KEY_CON			= (byte)0x10;
	static final byte GET_RSA_PUB_KEY_MOD_CON		= (byte)0x11;
	static final byte GET_RSA_PUB_KEY_EXP_CON		= (byte)0x12;
	static final byte GET_SECRET_KEY_MAC			= (byte)0x20;
	static final byte GET_RSA_PUB_KEY_MOD_DS		= (byte)0x21;
	static final byte GET_RSA_PUB_KEY_EXP_DS		= (byte)0x22;
	static final byte GET_EC_PUB_KEY_DS				= (byte)0x23;
	static final byte GET_SHARE_SECRET				= (byte)0x30;
	static final byte GET_SECRET_KEY_WRAP			= (byte)0x40;
	static final byte GET_APPLET_INFO				= (byte)0x90;
	
	//Types of all keys!
	static final byte P2_DEM_AUTH_AES_128			= (byte)0x01;
	
	static final byte P2_DEM_CON_AES_128			= (byte)0x11;
	static final byte P2_DEM_CON_AES_192			= (byte)0x12;
	static final byte P2_DEM_CON_AES_256			= (byte)0x13;
	static final byte P2_DEM_CON_TDES				= (byte)0x14;
	
	static final byte P2_DEM_MAC_TDES				= (byte)0x21;
	static final byte P2_DEM_MAC_AES_128			= (byte)0x22;
	static final byte P2_DEM_MAC_AES_192			= (byte)0x23;
	static final byte P2_DEM_MAC_AES_256			= (byte)0x24;
	static final byte P2_DEM_MAC_HMAC				= (byte)0x25;

	static final byte P2_DEM_PUB_RSA_1024_MOD		= (byte)0x31;
	static final byte P2_DEM_PUB_RSA_2048_MOD		= (byte)0x32;
	static final byte P2_DEM_PUB_RSA_1024_EXP		= (byte)0x33;
	static final byte P2_DEM_PUB_RSA_2048_EXP		= (byte)0x34;
	
	static final byte P2_DEM_PUB_ECDSA				= (byte)0x35;
//	static final byte P2_DEM_PUB_ECDH				= (byte)0x36;
	
	static final byte P2_DEM_WRAP_AES_256			= (byte)0x41;
	static final byte P2_DESTROY_KEY				= (byte)0xFF;

	static final byte P2_SET_PIN					= (byte)0x41;

	//MSE Parameter 
	static final byte P1_MSE_SET 					= (byte)0xf1;
	static final byte P1_MSE_RESTORE				= (byte)0xf3;
	static final byte P2_DSA						= (byte)0xB6;
	static final byte P2_HASH						= (byte)0xAA;
	static final byte P2_CON						= (byte)0xB8;
	
	//PSO Operation
	static final short P1P2_PSO_ENC				= (short)0x8680;
	static final short P1P2_PSO_DEC				= (short)0x8086;
	static final short P1P2_PSO_DS					= (short)0x9E9A;
	static final short P1P2_PSO_HASH				= (short)0x9080;
	static final short P1P2_PSO_VERIFY_DS			= (short)0x00A8;
	
	//Check Header
	static final byte CHECK_P1						= (byte)0x01;
	static final byte CHECK_P2						= (byte)0x02;
	static final byte CHECK_P1P2					= (byte)0x04;
	static final byte CHECK_LC						= (byte)0x08;
	
	//Generate KeyPair
	static final byte GENERATE_KEYPAIR_RSA			= (byte)0x00;
	static final byte GENERATE_KEYPAIR_ECP			= (byte)0x10;
	
	static final byte GENERATE_KEYPAIR_RSA_2048_SIGN 	 = (byte)0x01;
	static final byte GENERATE_KEYPAIR_RSA_CRT_2048_SIGN = (byte)0x02;
	static final byte GENERATE_KEYPAIR_RSA_2048_CON	     = (byte)0x03;
	static final byte GENERATE_KEYPAIR_RSA_CRT_2048_CON	 = (byte)0x04;
	
	static final byte GENERATE_KEYPAIR_ECP_192		= (byte)0x11;
	static final byte GENERATE_KEYPAIR_ECP_224		= (byte)0x12;
	static final byte GENERATE_KEYPAIR_ECP_256		= (byte)0x13;
	static final byte GENERATE_KEYPAIR_ECP_384		= (byte)0x14;
	static final byte GENERATE_KEYPAIR_ECP_521		= (byte)0x15;
	
	//algorithm index value
	static final byte ALG_SHA_256 					= (byte)0x03;
	static final byte ALG_AES_BLOCK_128_CBC_NOPAD 	= (byte)0x01;
	static final byte ALG_AES_MAC_128_NOPAD 		= (byte)0x02;
	
	//Java Card 3.0.4
	//KeyBilder
//	static final short LENGTH_EC_FP_521				= (short)521;
	static final short TEMP_BUFFER_MAX_LENGTH		= (short)0x0140;
	
	static final short MIN_SEED_LENGTH				= (short)0x0028;
	
	private static byte 			d_instanceCounter;
	
	private byte 					d_appletStatus;			//Persistent, keeps the applet's current state.
	private byte[] 					d_OperationState;		//Volatile, keeps the applet's current operations state.
	private byte[] 					d_SecurityEnvironment;	//Volatile, holds the algorithmic information.
	private byte[]					d_shareSecretCSP;
	private CSP[] 					d_KeyContainers;		//A collection of four key containers that holds CSPs for DEM-AUTH key, DEM-WRAP key, DEM-MAC key, and DEM-3P-PUB key.
	private Object[] 				d_KeyRefs;				//Holds all types of keys and keypairs reference!
	private RandomData random;
	private Cipher[] 				d_CipherRefs;			//Holds all types of Ciphers reference!
	private MessageDigest[]			d_DigestRefs;			
	private Signature[]				d_SignatureRefs;		//Holds all types of Signatures reference!
	private KeyAgreement 			d_keyAgreement;
	private byte[] 					d_FlagArray;			//Volatile, checking variable!
	private byte[] 					d_tempBuffer;			//Volatile, holds all intermediate data.
	
	//for garbage collection
	private boolean 				d_MemoryGarbage;
	private boolean	isShareSecret;
	//CMAC
    private byte[] d_sCounterSCP03;
    private byte[] d_cMACSessionKey;
    private byte[] d_CardChallenge;
    
    private RSAPublicKey rsaPublicKey;
    
	/**
	 * This is the Constructor of DemoApplet. All objects reference and array initialization done here.
	 * @param bArray
	 * @param bOffset
	 * @param bLength
	 * @author Rakeb, Mostak
	 */
	protected DemoApplet(byte[] bArray, short bOffset, byte bLength) {
		d_shareSecretCSP		= new byte[68];
		d_KeyContainers			= new CSP[5];
		d_sCounterSCP03 		= new byte[3];
		d_CardChallenge 		= JCSystem.makeTransientByteArray(Constants.BLOCK_SIZE_08, JCSystem.CLEAR_ON_DESELECT); 
		d_SecurityEnvironment	= JCSystem.makeTransientByteArray((short)0x0003, JCSystem.CLEAR_ON_DESELECT);
		d_OperationState		= JCSystem.makeTransientByteArray((short)0x0002, JCSystem.CLEAR_ON_DESELECT);
		d_FlagArray 			= JCSystem.makeTransientByteArray((short)0x0005, JCSystem.CLEAR_ON_DESELECT);
		
//		d_FlagArray[OFFSET_AC_FLAG] = Constants.TRUE; // PIN verification is required
		
		d_KeyContainers[OFFSET_CSP_DEM_AUTH]		= new CSP(Constants.CSP_DEM_AUTH_KEY_MAX_LEN, Constants.TRUE);
		d_KeyContainers[OFFSET_CSP_DEM_MAC]			= new CSP(Constants.CSP_DEM_MAC_KEY_MAX_LEN, Constants.TRUE);
		d_KeyContainers[OFFSET_CSP_DEM_CON_SECRET] 	= new CSP(Constants.CSP_DEM_WRAP_KEY_MAX_LEN, Constants.TRUE);		
		d_KeyContainers[OFFSET_CSP_DEM_KEY_WRAP] 	= new CSP(Constants.CSP_DEM_CON_SECRET_MAX_LEN, Constants.TRUE);	
		d_KeyContainers[OFFSET_CSP_DEM_3P_PUB] 		= new CSP(Constants.CSP_DEM_3P_PUB_MAX_LEN, Constants.FALSE);
		
		//Default AUTH BASE Key: Initialize
		Util.arrayCopyNonAtomic(Constants.BASE_AUTH_KEY, Constants.OFFSET_ZERO, d_KeyContainers[OFFSET_CSP_DEM_AUTH].c_body, Constants.OFFSET_ZERO, Constants.BLOCK_SIZE_16); 
		//SCP-03
		d_KeyContainers[OFFSET_CSP_DEM_AUTH].c_keyType = KeyBuilder.TYPE_AES;
		d_KeyContainers[OFFSET_CSP_DEM_AUTH].c_storedLen = KeyBuilder.LENGTH_AES_128;
		
		//Default WRAP BASE Key:
		Util.arrayCopyNonAtomic(Constants.BASE_WRAP_KEY, Constants.OFFSET_ZERO, d_KeyContainers[OFFSET_CSP_DEM_KEY_WRAP].c_body, Constants.OFFSET_ZERO, Constants.BLOCK_SIZE_32); 
		d_KeyContainers[OFFSET_CSP_DEM_KEY_WRAP].c_keyType = KeyBuilder.TYPE_AES;
		d_KeyContainers[OFFSET_CSP_DEM_KEY_WRAP].c_storedLen = KeyBuilder.LENGTH_AES_256;
		
		d_KeyRefs		= new Object[(short)0x0007];
		d_CipherRefs	= new Cipher[(short)0x0006];	
		d_DigestRefs	= new MessageDigest[(short)0x0002];
		d_SignatureRefs	= new Signature[(short)0x0005];			
		
		if(d_tempBuffer == null) {
    		d_tempBuffer = JCSystem.makeTransientByteArray(TEMP_BUFFER_MAX_LENGTH, JCSystem.CLEAR_ON_RESET);
    		d_instanceCounter = (byte)0x01;
//    		d_sCounter = (short)1; // SCP-02
    	} else {
    		d_instanceCounter += (byte)0x01;
    	}
		
        d_appletStatus = APP_STATUS_INITIALIZED;
        
        //key instance
        d_KeyRefs[OFFSET_KEY_DES] = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_DES3_3KEY, false);
        d_KeyRefs[OFFSET_KEY_AES] = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
        
        d_KeyRefs[OFFSET_KEYPAIR_DS] 		= new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);//for sign verify
        d_KeyRefs[OFFSET_KEYPAIR_RSA_WRAP] 	= new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);//for enc dec.
        
        random = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        //cipher instance
        d_CipherRefs[OFFSET_CIPHER_DES_CBC] = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
        d_CipherRefs[OFFSET_CIPHER_DES_ECB] = Cipher.getInstance(Cipher.ALG_DES_ECB_ISO9797_M2, false);
        d_CipherRefs[OFFSET_CIPHER_AES_CBC] = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        d_CipherRefs[OFFSET_CIPHER_AES_ECB] = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);   
        d_CipherRefs[OFFSET_CIPHER_RSA] 	= Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        
        d_CipherRefs[OFFSET_CIPHER_SCP02_DES_CBC] = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
        
        //digest instance
        d_DigestRefs[OFFSET_DIGEST_SHA1] = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        d_DigestRefs[OFFSET_DIGEST_SHA2] = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        
        //Signature instance
        d_SignatureRefs[OFFSET_SIGN_MAC_AES] 	= Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);
        d_SignatureRefs[OFFSET_SIGN_MAC_3DES] 	= Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_1_M2_ALG3, false);
        
        //SCP-02/SCP-03 Session Key;
        d_cMACSessionKey 	= JCSystem.makeTransientByteArray(Constants.BLOCK_SIZE_16, JCSystem.CLEAR_ON_DESELECT);
//        d_encSessionKey 	= JCSystem.makeTransientByteArray(Constants.BLOCK_SIZE_16, JCSystem.CLEAR_ON_DESELECT); // SCP-02
        
        /*
         * Comment for debug DemoApplet in JCOP
         */
        d_KeyRefs[OFFSET_KEY_HMAC] = (HMACKey)KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT, KeyBuilder.LENGTH_HMAC_SHA_512_BLOCK_128, false);
//        ((HMACKey)(d_KeyRefs[OFFSET_KEY_HMAC])).setKey(d_tempBuffer, Constants.OFFSET_ZERO, Constants.BLOCK_SIZE_32);
//        d_KeyRefs[OFFSET_KEYPAIR_DS] = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_521);
        
	    //For EC and RSA(signature verification) a new KeyPair of EC and public key of RSA must be
	    //generated to construct a new public key from a remote public key
	    d_KeyRefs[OFFSET_KEYPAIR_3P]	= new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_521);
        rsaPublicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
        d_keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        
        d_SignatureRefs[OFFSET_SIGN_MAC_HMAC] 	= Signature.getInstance(Signature.ALG_HMAC_SHA_512, false);
        d_SignatureRefs[OFFSET_SIGN_RSA] 		= Signature.getInstance(Signature.ALG_RSA_SHA_512_PKCS1_PSS, false);
        d_SignatureRefs[OFFSET_SIGN_EC] 		= Signature.getInstance(Signature.ALG_ECDSA_SHA_512, false);
        /*
         * End
         */
        
        //variable L, subKeys (K1 || K2) use into generateCMAC
//        cmacL = JCSystem.makeTransientByteArray(Constants.BLOCK_SIZE_16, JCSystem.CLEAR_ON_DESELECT);
//        cmacSubKeys = JCSystem.makeTransientByteArray(Constants.BLOCK_SIZE_32, JCSystem.CLEAR_ON_DESELECT);
        
        d_MemoryGarbage = false;
        
        d_OperationState[OFFSET_STATE] = Constants.STATE_IDLE;
        
		register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}
	
    public boolean select() {
    	if(!super.select()) {
    		return false;
    	}
    	return true;
    }
    
    public void deselect() {
    	super.deselect();
    }
    
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new DemoApplet(bArray, bOffset, bLength);
	}
	
	public void uninstall() {
		if(d_instanceCounter <= (byte)0x01) {
			d_tempBuffer = null;
		} else {
			d_instanceCounter -= (byte)0x01;
		}
	}
	
	
	public void process(APDU apdu) {
		if((d_MemoryGarbage == true) && JCSystem.isObjectDeletionSupported()) {
			JCSystem.requestObjectDeletion();
			d_MemoryGarbage = false;
		}
		
		checkAppletState(apdu);
		
		byte[] buf = apdu.getBuffer();
		byte classByte = buf[ISO7816.OFFSET_CLA];
		byte ins = buf[ISO7816.OFFSET_INS];
		
		if(classByte >= (byte)0x00 && classByte <= (byte)0x03){
			if(ins==INS_INITIALIZE_UPDATE || ins==INS_EXTERNAL_AUTHENTICATION){
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		}else if(classByte >= (byte)0x80 && classByte <= (byte)0x83){
			if(ins != INS_INITIALIZE_UPDATE){
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		}else if(classByte >= (byte)0x84 && classByte <= (byte)0x87){
			if(ins != INS_EXTERNAL_AUTHENTICATION){
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		}else{
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		checkOperationState(apdu);
		
		switch (ins) {
		case INS_PUT_DATA:
			if(buf[ISO7816.OFFSET_P1] != (byte)0x01) {
		    	ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		    }
			if(buf[ISO7816.OFFSET_P2]== P2_DESTROY_KEY){
				if(buf[ISO7816.OFFSET_LC]!= (byte)0x00){
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				destroy();
			}else{
				putData(apdu);
			}
			break;
		case INS_GET_DATA:
			getData(apdu);
			break;
		case INS_GET_CHALLANGE:
			getChallenge(apdu);
			break;
		case INS_MSE:
			mse(apdu);
			break;
		case INS_PSO:
			if(d_OperationState[OFFSET_MSE] == Constants.FALSE) {
				ISOException.throwIt(Constants.SW_SE_NOT_RESTORED);
			}
			pso(apdu);
			break;
		case INS_GENERATE_KEY_PAIR:
			generateKeyPair(apdu);
			break;
		case INS_INITIALIZE_UPDATE:
			checkAPDUHeader(apdu, (byte)(CHECK_P1P2| CHECK_LC), (byte)0x00, (byte)0x00, (short)0x0000, (byte)0x08);
			initializeUpdateSCP03(apdu);
			break;
		case INS_EXTERNAL_AUTHENTICATION:
			checkAPDUHeader(apdu, (byte)(CHECK_P1P2| CHECK_LC), (byte)0x00, (byte)0x00, (short)0x0000, (byte)0x10);
			externalAuthenticateSCP03(apdu);
			break;
		case INS_GENERAL_AUTHENTICATION:
			keyAgreement(apdu);
			break;
		case INS_SELECT_APPLET:
			checkAPDUHeader(apdu, (byte)(CHECK_P1P2), (byte)0x00, (byte)0x00, (short)0x0400, (byte)0x00);
			if (selectingApplet()) {
				d_OperationState[OFFSET_STATE] = Constants.STATE_IDLE;
				return;
			}
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	/**
	 * Load or PUT DATA/Key into a Key containers.
	 * <p>If the incoming data is secret key, 
	 * then it first unwrapped and then loaded into secret Key containers. 
	 * The unwrapping key value is stored into <code>DEM-KEY-WRAP</code> Container, and
	 * the unwrapping mechanism will be foretold in <code>MSE</code>
	 * 
	 * @param apdu
	 * 
	 * @author Rakeb
	 * 
	 * @exception CryptoException
	 *                with the following reason codes:
	 *                <ul>
	 *                <li><code>CryptoException.NO_SUCH_ALGORITHM</code> if
     *                the requested algorithm is not supported or shared access
     *                mode is not supported.
     *                <li><code>CryptoException.ILLEGAL_VALUE</code> if
     *                <code>theMode</code> option is an undefined value or if
     *                the <code>Key</code> is inconsistent with the
     *                <code>Cipher</code> implementation.
     *                <li><code>CryptoException.UNINITIALIZED_KEY</code> if
	 *                key not initialized or <code>theKey</code> instance is uninitialized.
	 *                <li><code>CryptoException.INVALID_INIT</code> if this
	 *                <code>Cipher</code> object is not initialized.
	 *                <li><code>CryptoException.ILLEGAL_USE</code> if one of
	 *                the following conditions is met:
	 *                <ul>
	 *                <li>This <code>Cipher</code> algorithm does not pad the
	 *                message and the message is not block aligned.
	 *                <li>This <code>Cipher</code> algorithm does not pad the
	 *                message and no input data has been provided in
	 *                <code>inBuff</code> or via the <code>update()</code>
	 *                method.
	 *                <li>The input message length is not supported or the message value
	 *                is greater than or equal to the modulus.
	 *                <li>The decrypted data is not bounded by appropriate
	 *                padding bytes.
	 *                </ul>
	 *                </ul>
	 */
	private void putData(APDU apdu) {		
		byte[] apduBuffer = apdu.getBuffer();
		byte algoRef;
		byte checkFirstBit = (byte)(apduBuffer[ISO7816.OFFSET_P2] & (byte)0x80);
		byte p2 = apduBuffer[ISO7816.OFFSET_P2];
		short lcLen = (short)(0x00ff & apduBuffer[ISO7816.OFFSET_LC]);
		short dataLen = Constants.OFFSET_ZERO;
//		boolean putFirstPart = false;
		
		apdu.setIncomingAndReceive();
		
		if(checkFirstBit!=DEMO_KEYS){
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
		
		
    	/*********update demo keys****************/	    	
		//
    	// Checks B6 B5 B4 Bits
    	//
		byte checkB6B5B4Bits = (byte)(p2 & (byte)0x70);
		
		Key key = null;
		Cipher cipher = null;

		//
		// This part is for unwrapping the encrypted key and put it into d_tempBuffer from apduBuffer.
		//
		try {
			if(checkB6B5B4Bits == PUB_KEY) {
				dataLen = lcLen;
			} else {
				if(d_OperationState[OFFSET_MSE] == Constants.FALSE) {
					ISOException.throwIt(Constants.SW_SE_NOT_RESTORED);
				}
				algoRef = d_SecurityEnvironment[OFFSET_SE_CON];
				if(algoRef == Constants.ALG_REF_WRAP_AES) {
					if(d_KeyContainers[OFFSET_CSP_DEM_KEY_WRAP].c_keyType != KeyBuilder.TYPE_AES){
						ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
					}
					AESKey aesKey = (AESKey) d_KeyRefs[OFFSET_KEY_AES];
					if(aesKey.getSize()!=KeyBuilder.LENGTH_AES_256){
						aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_256, false);
						d_KeyRefs[OFFSET_KEY_AES] = aesKey;
						d_MemoryGarbage = true;
					}
					aesKey.setKey(d_KeyContainers[OFFSET_CSP_DEM_KEY_WRAP].c_body, Constants.OFFSET_ZERO);
					key = aesKey;
					Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, d_tempBuffer, Constants.OFFSET_ZERO, lcLen);
				} else if ((algoRef == Constants.CON_ALG_RSA_MIN || algoRef == Constants.CON_ALG_RSA_MAX)&&(p2 == P2_DEM_MAC_TDES || p2 == P2_DEM_CON_TDES)){
					if(d_FlagArray[OFFSET_PUT_FIRST_PART] == Constants.FALSE && lcLen== (short)128){
						Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, d_tempBuffer, Constants.OFFSET_ZERO, lcLen);
						d_FlagArray[OFFSET_PUT_FIRST_PART] = Constants.TRUE;
						ISOException.throwIt(ISO7816.SW_NO_ERROR);
					}else if(d_FlagArray[OFFSET_PUT_FIRST_PART] == Constants.TRUE && lcLen== (short)128){
						Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, d_tempBuffer, lcLen, lcLen);
						lcLen = (short)256;
						d_FlagArray[OFFSET_PUT_FIRST_PART] = Constants.FALSE;
					}else{
						ISOException.throwIt(ISO7816.SW_WRONG_DATA);
					}
					key = ((KeyPair) d_KeyRefs[OFFSET_KEYPAIR_RSA_WRAP]).getPrivate();
				}else{
					ISOException.throwIt(Constants.SW_ALG_NOT_SUPPORTED);
				}
				
//				if(d_FlagArray[OFFSET_PUT_FIRST_PART] != Constants.FALSE){
//					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
//				}
				
				cipher	= getCipherInstance(OFFSET_SE_CON);
				cipher.init(key, Cipher.MODE_DECRYPT);
				dataLen = cipher.doFinal(d_tempBuffer, Constants.OFFSET_ZERO, lcLen, apduBuffer, Constants.OFFSET_ZERO);
				
				Util.arrayCopyNonAtomic(apduBuffer, Constants.OFFSET_ZERO, d_tempBuffer, Constants.OFFSET_ZERO, dataLen);
				if(cipher.getAlgorithm()==Cipher.ALG_RSA_NOPAD){
					apduBuffer[0]=(byte)0x80;
					Util.arrayFillNonAtomic(apduBuffer, (short)1, (short)240, Constants.FALSE);
					if(Util.arrayCompare(d_tempBuffer, Constants.BLOCK_SIZE_16, apduBuffer, Constants.OFFSET_ZERO, (short)240)==Constants.FALSE){
						dataLen = Constants.BLOCK_SIZE_16;
					}else if(Util.arrayCompare(d_tempBuffer, Constants.BLOCK_SIZE_24, apduBuffer, Constants.OFFSET_ZERO, (short)232)==Constants.FALSE){
						dataLen = Constants.BLOCK_SIZE_24;
					}else{
						ISOException.throwIt(ISO7816.SW_WRONG_DATA);
					}
				};
			}
		} catch(CryptoException e){
			ISOException.throwIt((short) (Constants.SW_INVALID_DATA_BLOCK | e.getReason()));
		}
		
		switch (p2) {
			// AUTH key
			case P2_DEM_AUTH_AES_128:
				if(dataLen != Constants.BLOCK_SIZE_16) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				
				JCSystem.beginTransaction();
				//SCP-03
				d_KeyContainers[OFFSET_CSP_DEM_AUTH].c_keyType = KeyBuilder.TYPE_AES;
				d_KeyContainers[OFFSET_CSP_DEM_AUTH].c_storedLen = KeyBuilder.LENGTH_AES_128;
				Util.arrayCopyNonAtomic(d_tempBuffer, Constants.OFFSET_ZERO, d_KeyContainers[OFFSET_CSP_DEM_AUTH].c_body, Constants.OFFSET_ZERO, dataLen);
				JCSystem.commitTransaction();	
				Util.arrayFillNonAtomic(d_sCounterSCP03, Constants.OFFSET_ZERO, (short)3, (byte)0x00);
				break;
				
			// MAC key
			case P2_DEM_MAC_TDES:
				if((dataLen != Constants.LENGTH_DES3_2KEY) && (dataLen != Constants.LENGTH_DES3_3KEY)) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				JCSystem.beginTransaction();
				d_KeyContainers[OFFSET_CSP_DEM_MAC].c_keyType = KeyBuilder.TYPE_DES;
				d_KeyContainers[OFFSET_CSP_DEM_MAC].c_storedLen = (short) (dataLen * 8);
				Util.arrayCopyNonAtomic(d_tempBuffer, Constants.OFFSET_ZERO, d_KeyContainers[OFFSET_CSP_DEM_MAC].c_body, Constants.OFFSET_ZERO, dataLen);
				JCSystem.commitTransaction();
				break;
			case P2_DEM_MAC_AES_128:
				if(dataLen != Constants.LENGTH_AES_128) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
			case P2_DEM_MAC_AES_192:
				if(p2 == P2_DEM_MAC_AES_192 && dataLen != Constants.LENGTH_AES_192) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
			case P2_DEM_MAC_AES_256:
				if(p2 == P2_DEM_MAC_AES_256 && dataLen != Constants.LENGTH_AES_256) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				
				JCSystem.beginTransaction();
				d_KeyContainers[OFFSET_CSP_DEM_MAC].c_keyType = KeyBuilder.TYPE_AES;
				d_KeyContainers[OFFSET_CSP_DEM_MAC].c_storedLen = (short) (dataLen * 8);
				Util.arrayCopyNonAtomic(d_tempBuffer, Constants.OFFSET_ZERO, d_KeyContainers[OFFSET_CSP_DEM_MAC].c_body, Constants.OFFSET_ZERO, dataLen);
				JCSystem.commitTransaction();
				break;
			case P2_DEM_MAC_HMAC:
				if(dataLen <Constants.BLOCK_SIZE_16 || dataLen > Constants.BLOCK_SIZE_32) {		//H-MAC Key Minimum 16 bytes and  Maximum 32 bytes Support 
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				JCSystem.beginTransaction();
				d_KeyContainers[OFFSET_CSP_DEM_MAC].c_keyType = KeyBuilder.TYPE_HMAC;
				d_KeyContainers[OFFSET_CSP_DEM_MAC].c_storedLen = (short)(dataLen*8); //stored length in byte
				Util.arrayCopyNonAtomic(d_tempBuffer, Constants.OFFSET_ZERO, d_KeyContainers[OFFSET_CSP_DEM_MAC].c_body, Constants.OFFSET_ZERO, dataLen);
				JCSystem.commitTransaction();
				break;
				
			// CON key
			case P2_DEM_CON_TDES:
				if((dataLen != Constants.LENGTH_DES3_2KEY) && (dataLen != Constants.LENGTH_DES3_3KEY)) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				JCSystem.beginTransaction();
				d_KeyContainers[OFFSET_CSP_DEM_CON_SECRET].c_keyType = KeyBuilder.TYPE_DES;
				d_KeyContainers[OFFSET_CSP_DEM_CON_SECRET].c_storedLen = (short) (dataLen * 8);
				Util.arrayCopyNonAtomic(d_tempBuffer, Constants.OFFSET_ZERO, d_KeyContainers[OFFSET_CSP_DEM_CON_SECRET].c_body, Constants.OFFSET_ZERO, dataLen);
				JCSystem.commitTransaction();
				break;
			case P2_DEM_CON_AES_128:
				if(dataLen != Constants.LENGTH_AES_128) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
			case P2_DEM_CON_AES_192:
				if(p2 == P2_DEM_CON_AES_192 && dataLen != Constants.LENGTH_AES_192) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
			case P2_DEM_CON_AES_256:
				if(p2 == P2_DEM_CON_AES_256 && dataLen != Constants.LENGTH_AES_256) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				JCSystem.beginTransaction();
				d_KeyContainers[OFFSET_CSP_DEM_CON_SECRET].c_keyType = KeyBuilder.TYPE_AES;
				d_KeyContainers[OFFSET_CSP_DEM_CON_SECRET].c_storedLen = (short) (dataLen * 8);
				Util.arrayCopyNonAtomic(d_tempBuffer, Constants.OFFSET_ZERO, d_KeyContainers[OFFSET_CSP_DEM_CON_SECRET].c_body, Constants.OFFSET_ZERO, dataLen);
				JCSystem.commitTransaction();
				break;
				
			//3P Public Key
			case P2_DEM_PUB_RSA_1024_MOD:
				if(dataLen != Constants.LENGTH_RSA_1024) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				JCSystem.beginTransaction();
				Util.arrayCopyNonAtomic(apduBuffer, (short)ISO7816.OFFSET_CDATA, d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_body, Constants.OFFSET_ZERO, dataLen);
				d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_storedLen	= Constants.OFFSET_ZERO; // By force key not initialized
				d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_keyType	= (byte) 0x00; // By force key not initialized 
				JCSystem.commitTransaction();
				
				d_FlagArray[OFFSET_1024_MODULUS_CHECKED] = Constants.TRUE;
				d_OperationState[OFFSET_STATE] = Constants.STATE_PUT_DATA;
				break;
				
			case P2_DEM_PUB_RSA_1024_EXP:
				if(d_FlagArray[OFFSET_1024_MODULUS_CHECKED] == Constants.FALSE) {
					ISOException.throwIt(Constants.SW_MUDULUS_NOT_INITIALIZED);
				}
				if(dataLen > Constants.LENGTH_RSA_1024) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
	
				d_FlagArray[OFFSET_1024_MODULUS_CHECKED] = Constants.FALSE;
				JCSystem.beginTransaction();
				d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_keyType = KeyBuilder.TYPE_RSA_PUBLIC; // Key initialized
				d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_storedLen = (short)((short)1024 + (short)(Constants.BLOCK_SIZE_08*dataLen));
				Util.arrayCopyNonAtomic(apduBuffer, (short)ISO7816.OFFSET_CDATA, d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_body, Constants.LENGTH_RSA_1024, dataLen);
				JCSystem.commitTransaction();
				d_OperationState[OFFSET_STATE] = Constants.STATE_AUTHENTICATE_IDLE;
				break;
				
			case P2_DEM_PUB_RSA_2048_MOD:
				if(dataLen != (short)129) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				else if(apduBuffer[ISO7816.OFFSET_CDATA] == (byte)0x81) { // && d_FlagArray[OFFSET_MODULUS_CHECK] == Constants.FALSE) {
					JCSystem.beginTransaction();
					d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_keyType	= (byte) 0x00;	// By force key not initialization
					d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_storedLen 	= (byte) 0x00;	// By force key not initialization
					Util.arrayCopyNonAtomic(apduBuffer, (short)(ISO7816.OFFSET_CDATA +1), d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_body, Constants.OFFSET_ZERO, (short)128);
					JCSystem.commitTransaction();
					d_FlagArray[OFFSET_2048_MODULUS_CHECKED] = Constants.TRUE;
					d_OperationState[OFFSET_STATE] = Constants.STATE_PUT_DATA;
				}
				else if(apduBuffer[ISO7816.OFFSET_CDATA] == (byte)0x82 && (d_FlagArray[OFFSET_2048_MODULUS_CHECKED] == Constants.TRUE)) {
					JCSystem.beginTransaction();
					Util.arrayCopyNonAtomic(apduBuffer, (short)(ISO7816.OFFSET_CDATA +1), d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_body, (short)128, (short)128);
					d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_storedLen = Constants.LENGTH_RSA_2048;
					JCSystem.commitTransaction();
				} else {
					ISOException.throwIt(Constants.SW_MUDULUS_NOT_INITIALIZED);
				}
				break;
				
			case P2_DEM_PUB_RSA_2048_EXP:
				if(d_FlagArray[OFFSET_2048_MODULUS_CHECKED] == Constants.FALSE) {
					ISOException.throwIt(Constants.SW_MUDULUS_NOT_INITIALIZED);
				}
				if(d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_storedLen != Constants.LENGTH_RSA_2048) {
					ISOException.throwIt(Constants.SW_MUDULUS_NOT_INITIALIZED);
				}
				if(dataLen > Constants.LENGTH_RSA_2048) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				d_FlagArray[OFFSET_2048_MODULUS_CHECKED] = Constants.FALSE;
				JCSystem.beginTransaction();
				d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_keyType = KeyBuilder.TYPE_RSA_PUBLIC; // Key initialized
				d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_storedLen = (short)((short)2048 + (short)(Constants.BLOCK_SIZE_08*dataLen));
				Util.arrayCopyNonAtomic(apduBuffer, (short)ISO7816.OFFSET_CDATA, d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_body, Constants.LENGTH_RSA_2048, dataLen);
				JCSystem.commitTransaction();
				d_OperationState[OFFSET_STATE] = Constants.STATE_AUTHENTICATE_IDLE;
				break;
				
			case P2_DEM_PUB_ECDSA:
				if(dataLen <= 0 || dataLen > (short)133) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				JCSystem.beginTransaction();
				d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_keyType = KeyBuilder.TYPE_EC_FP_PUBLIC;
				d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_storedLen = (short)(dataLen*Constants.BLOCK_SIZE_08);
				Util.arrayCopyNonAtomic(apduBuffer, (short)ISO7816.OFFSET_CDATA, d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_body, Constants.OFFSET_ZERO, dataLen);
				JCSystem.commitTransaction();
				break;
				
			//WRAP key
			case P2_DEM_WRAP_AES_256:
				if(dataLen != Constants.LENGTH_AES_256) {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				JCSystem.beginTransaction();
				Util.arrayCopyNonAtomic(d_tempBuffer, Constants.OFFSET_ZERO, d_KeyContainers[OFFSET_CSP_DEM_KEY_WRAP].c_body, Constants.OFFSET_ZERO, dataLen);
				JCSystem.commitTransaction();
				break;
				
			default:
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
	}
	
	/**
	 * Retrieve the public key from the generated Key 
	 * pair (Both RSA and EC) and the current Operation State.
	 * @param apdu
	 * @author Rakeb
	 */
	private void getData(APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		byte algoRef, p2 = apduBuffer[ISO7816.OFFSET_P2];
		if(apduBuffer[ISO7816.OFFSET_P1] != (byte)0x01) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		Cipher cipher;
		Key key = null;
		CSP csp = null;
		short responseLength = (short)0;
		KeyPair keypair = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_RSA_WRAP];
		RSAPublicKey rsaPublicKeyCon = (RSAPublicKey) keypair.getPublic();
		
		ECPublicKey ecPublicKey;
		RSAPublicKey rsaPublicKeySign;
		keypair = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_DS];
		
		switch (p2) {
		case GET_OPERATION_STATE:
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) 1);
			
			apduBuffer[Constants.OFFSET_ZERO] = d_OperationState[OFFSET_STATE];
			apdu.sendBytesLong(apduBuffer, Constants.OFFSET_ZERO, (short) 1);
			
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
		//AUTH key
		case GET_SECRET_KEY_AUTH:
			csp = d_KeyContainers[OFFSET_CSP_DEM_AUTH];
			if(csp.c_storedLen <= Constants.OFFSET_ZERO) {
				ISOException.throwIt(Constants.SW_KEY_NOT_INITIALIZE);
			}
			responseLength = Util.arrayCopyNonAtomic(csp.c_body, Constants.OFFSET_ZERO, d_tempBuffer, Constants.OFFSET_ZERO, (short)(csp.c_storedLen/8));
			break;
			
		// MAC key
		case GET_SECRET_KEY_MAC:
			csp = d_KeyContainers[OFFSET_CSP_DEM_MAC];
			if(csp.c_storedLen <= Constants.OFFSET_ZERO) {
				ISOException.throwIt(Constants.SW_KEY_NOT_INITIALIZE);
			}
			responseLength = Util.arrayCopyNonAtomic(csp.c_body, Constants.OFFSET_ZERO, d_tempBuffer, Constants.OFFSET_ZERO, (short)(csp.c_storedLen/8));
			break;
			
		// CON key
		case GET_SECRET_KEY_CON:
			csp = d_KeyContainers[OFFSET_CSP_DEM_CON_SECRET];
			if(csp.c_storedLen <= Constants.OFFSET_ZERO) {
				ISOException.throwIt(Constants.SW_KEY_NOT_INITIALIZE);
			}
			responseLength = Util.arrayCopyNonAtomic(csp.c_body, Constants.OFFSET_ZERO, d_tempBuffer, Constants.OFFSET_ZERO, (short)(csp.c_storedLen/8));
			break;
			//WRAP key
		case GET_SECRET_KEY_WRAP:
			csp = d_KeyContainers[OFFSET_CSP_DEM_KEY_WRAP];
			if(csp.c_storedLen <= Constants.OFFSET_ZERO) {
				ISOException.throwIt(Constants.SW_KEY_NOT_INITIALIZE);
			}
			responseLength = Util.arrayCopyNonAtomic(csp.c_body, Constants.OFFSET_ZERO, d_tempBuffer, Constants.OFFSET_ZERO, (short)(csp.c_storedLen/8));
			break;
		case GET_SHARE_SECRET:
			if(isShareSecret){
				responseLength = Util.arrayCopyNonAtomic(d_shareSecretCSP, Constants.OFFSET_ZERO, d_tempBuffer, Constants.OFFSET_ZERO, (short)20);
			}else{
				ISOException.throwIt(Constants.SW_KEY_NOT_INITIALIZE);
			}
			break;
		case GET_RSA_PUB_KEY_MOD_DS:
			if(keypair.getPublic().getType()==KeyBuilder.TYPE_RSA_PUBLIC){
				rsaPublicKeySign = (RSAPublicKey) keypair.getPublic();
				if(!rsaPublicKeySign.isInitialized()) {
					ISOException.throwIt(Constants.SW_KEY_NOT_INITIALIZE);
				}
				responseLength = rsaPublicKeySign.getModulus(d_tempBuffer, Constants.OFFSET_ZERO);
			}else{
				ISOException.throwIt(Constants.SW_KEY_NOT_INITIALIZE);
			}
			break;
		case GET_RSA_PUB_KEY_EXP_DS:
			if(keypair.getPublic().getType()==KeyBuilder.TYPE_RSA_PUBLIC){
				rsaPublicKeySign = (RSAPublicKey) keypair.getPublic();
				if(!rsaPublicKeySign.isInitialized()) {
					ISOException.throwIt(Constants.SW_KEY_NOT_INITIALIZE);
				}
				responseLength = rsaPublicKeySign.getExponent(d_tempBuffer, Constants.OFFSET_ZERO);
			}else{
				ISOException.throwIt(Constants.SW_KEY_NOT_INITIALIZE);
			}
			break;
		case GET_RSA_PUB_KEY_MOD_CON:
			if(!rsaPublicKeyCon.isInitialized()) {
				ISOException.throwIt(Constants.SW_KEY_NOT_INITIALIZE);
			}
			responseLength = rsaPublicKeyCon.getModulus(d_tempBuffer, Constants.OFFSET_ZERO);
			break;
		case GET_RSA_PUB_KEY_EXP_CON:
			if(!rsaPublicKeyCon.isInitialized()) {
				ISOException.throwIt(Constants.SW_KEY_NOT_INITIALIZE);
			}
			responseLength = rsaPublicKeyCon.getExponent(d_tempBuffer, Constants.OFFSET_ZERO);
			break;
		case GET_EC_PUB_KEY_DS:
			if(keypair.getPublic().getType()==KeyBuilder.TYPE_EC_FP_PUBLIC){
				ecPublicKey = (ECPublicKey) keypair.getPublic();
				if(!ecPublicKey.isInitialized()) {
					ISOException.throwIt(Constants.SW_KEY_NOT_INITIALIZE);
				}
				responseLength = ecPublicKey.getW(d_tempBuffer, Constants.OFFSET_ZERO);
			}else{
				ISOException.throwIt(Constants.SW_KEY_NOT_INITIALIZE);
			}
			
			break;
		case GET_APPLET_INFO:
			responseLength = (short) Constants.APPLET_INFO.length;
			Util.arrayCopyNonAtomic(Constants.APPLET_INFO, Constants.OFFSET_ZERO, d_tempBuffer, Constants.OFFSET_ZERO, responseLength);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
		
		if(csp!=null || p2==GET_SHARE_SECRET){
			if(d_OperationState[OFFSET_MSE] == Constants.FALSE) {
				ISOException.throwIt(Constants.SW_SE_NOT_RESTORED);
			}
			algoRef = d_SecurityEnvironment[OFFSET_SE_CON];
			if(algoRef == Constants.ALG_REF_WRAP_AES) {
				AESKey aesKey = (AESKey) d_KeyRefs[OFFSET_KEY_AES];
				if(aesKey.getSize()!=KeyBuilder.LENGTH_AES_256){
					aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_256, false);
					d_KeyRefs[OFFSET_KEY_AES] = aesKey;
					d_MemoryGarbage = true;
				}
				aesKey.setKey(d_KeyContainers[OFFSET_CSP_DEM_KEY_WRAP].c_body, Constants.OFFSET_ZERO);
				key = aesKey;
			}else if ((algoRef == Constants.CON_ALG_RSA_MIN || algoRef == Constants.CON_ALG_RSA_MAX)&& p2==GET_SHARE_SECRET){
				ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
			}else if ((algoRef == Constants.CON_ALG_RSA_MIN || algoRef == Constants.CON_ALG_RSA_MAX)&& csp.c_keyType==KeyBuilder.TYPE_DES){
				if(d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_keyType != KeyBuilder.TYPE_RSA_PUBLIC) {
					ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
				}
				
				if(d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_storedLen < KeyBuilder.LENGTH_RSA_2048){
					ISOException.throwIt(Constants.SW_KEYPAIR_NOT_SUPPORTED);
				}
				
				if(rsaPublicKey.getSize() != KeyBuilder.LENGTH_RSA_2048) {
					rsaPublicKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
					d_MemoryGarbage = true;
				}
				
				rsaPublicKey.setModulus(d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_body, Constants.OFFSET_ZERO, (short)256);
				rsaPublicKey.setExponent(d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_body, (short)256, (short)((short)(d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_storedLen/8)-(short)256));
				
				key = rsaPublicKey;
				if(algoRef == Constants.CON_ALG_RSA_MIN) {
					if(csp.c_storedLen==KeyBuilder.LENGTH_DES3_2KEY){
						d_tempBuffer[Constants.BLOCK_SIZE_16] = (byte)0x80;
						Util.arrayFillNonAtomic(d_tempBuffer, (short)17, (short)240, (byte)0x00);
					}else{
						d_tempBuffer[Constants.BLOCK_SIZE_24] = (byte)0x80;
						Util.arrayFillNonAtomic(d_tempBuffer, (short)25, (short)232, (byte)0x00);
					}
					responseLength = (short)256;
				}
			}else{
				ISOException.throwIt(Constants.SW_ALG_NOT_SUPPORTED);
			}
			
			cipher	= getCipherInstance(OFFSET_SE_CON);
			cipher.init(key, Cipher.MODE_ENCRYPT);
			
			try {
				responseLength = cipher.doFinal(d_tempBuffer, Constants.OFFSET_ZERO, responseLength, d_tempBuffer, Constants.OFFSET_ZERO);
			} catch (CryptoException e) {
				ISOException.throwIt((short) (Constants.SW_INVALID_DATA_BLOCK | e.getReason()));
			}
		}
		
		apdu.setOutgoing();
		apdu.setOutgoingLength(responseLength);
		apdu.sendBytesLong(d_tempBuffer, Constants.OFFSET_ZERO, responseLength);
	}
	
	/**
	 * Generates random number of given length with or without seeding.
	 * @param apdu
	 * @author Mostak Ahmed
	 */
	private void getChallenge(APDU apdu){
		byte[] apduBuffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		//LC Check
		if(apduBuffer[ISO7816.OFFSET_CDATA]==(byte)0x10){
			checkAPDUHeader(apdu, (byte) (CHECK_P1P2), (byte) 0x00, (byte) 0x00,
					(short) 0x0000, (byte) 0x00);
		}else if(apduBuffer[ISO7816.OFFSET_CDATA]==(byte)0x30){
			checkAPDUHeader(apdu, (byte) (CHECK_P1P2 | CHECK_LC), (byte) 0x00, (byte) 0x00,
					(short) 0x0000, (byte) 0x02);
		}else{
			checkAPDUHeader(apdu, (byte) (CHECK_P1P2 | CHECK_LC), (byte) 0x00, (byte) 0x00,
					(short) 0x0000, (byte) 0x01);
		}
		
		short lc = (short) (apduBuffer[ISO7816.OFFSET_LC]&0x00ff);
		short le, sLen, offset = (short)ISO7816.OFFSET_CDATA;
		Key key = null;
		Cipher cipher;
		CSP wrapCSP = d_KeyContainers[OFFSET_CSP_DEM_KEY_WRAP];
		if(d_OperationState[OFFSET_MSE] == Constants.FALSE) {
			ISOException.throwIt(Constants.SW_SE_NOT_RESTORED);
		};
		switch(apduBuffer[offset]){
			case (byte)0x10:	//DRBG : Get new Random instance and initialize with seed value
				lc-=1;
				if(d_SecurityEnvironment[OFFSET_SE_CON] == Constants.ALG_REF_WRAP_AES) {
					if(wrapCSP.c_keyType != KeyBuilder.TYPE_AES){
						ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
					}
					AESKey aesKey = (AESKey) d_KeyRefs[OFFSET_KEY_AES];
					if(aesKey.getSize()!=KeyBuilder.LENGTH_AES_256){
						aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_256, false);
						d_KeyRefs[OFFSET_KEY_AES] = aesKey;
						d_MemoryGarbage = true;
					}
					aesKey.setKey(wrapCSP.c_body, Constants.OFFSET_ZERO);
					key = aesKey;
				}else{
					ISOException.throwIt(Constants.SW_ALG_NOT_SUPPORTED);
				}
				
				cipher	= getCipherInstance(OFFSET_SE_CON);
				cipher.init(key, Cipher.MODE_DECRYPT);
				offset+=1;
				sLen = cipher.doFinal(apduBuffer, offset, lc, d_tempBuffer, Constants.OFFSET_ZERO);
				if(sLen==Constants.LENGTH_SEED_AES_128
						|| sLen==Constants.LENGTH_SEED_AES_192
						|| sLen==Constants.LENGTH_SEED_AES_256){
				}else{
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}
				
				random = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
				d_MemoryGarbage = true;
				random.setSeed(d_tempBuffer, Constants.OFFSET_ZERO, sLen);
				break;
			case (byte)0x20:	//TRNG : Get new Random instance
				random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
				d_MemoryGarbage = true; 
				break;
			case (byte)0x30:
				if(random==null){
					ISOException.throwIt(ISO7816.SW_WRONG_DATA); //Change status word
				}
				offset+=1;
				le = (short) (apduBuffer[offset]&0x00ff);
				try{
					random.generateData(d_tempBuffer, Constants.OFFSET_ZERO, le);
				} catch(CryptoException e){
					ISOException.throwIt((short) (Constants.SW_INVALID_DATA_BLOCK | e.getReason()));
				}
				if(d_SecurityEnvironment[OFFSET_SE_CON] == Constants.ALG_REF_WRAP_AES) {
					if(wrapCSP.c_keyType != KeyBuilder.TYPE_AES){
						ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
					}
					AESKey aesKey = (AESKey) d_KeyRefs[OFFSET_KEY_AES];
					if(aesKey.getSize()!=KeyBuilder.LENGTH_AES_256){
						aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_256, false);
						d_KeyRefs[OFFSET_KEY_AES] = aesKey;
						d_MemoryGarbage = true;
					}
					aesKey.setKey(wrapCSP.c_body, Constants.OFFSET_ZERO);
					key = aesKey;
				}else{
					ISOException.throwIt(Constants.SW_ALG_NOT_SUPPORTED);
				}
				cipher	= getCipherInstance(OFFSET_SE_CON);
				cipher.init(key, Cipher.MODE_ENCRYPT);
				sLen = cipher.doFinal(d_tempBuffer, Constants.OFFSET_ZERO, le, apduBuffer, Constants.OFFSET_ZERO);
				apdu.setOutgoingAndSend(Constants.OFFSET_ZERO, sLen);
				break;
			case (byte)0x40:
				random = null;
				break;
			case (byte)0x50:
				random = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
				d_MemoryGarbage = true;
				break;
			default:
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
	}
	
	/**
	 * Checks the applet's state for requested command.
	 * @param apdu
	 */
	private void checkAppletState(APDU apdu) {
		switch(d_appletStatus) {
		case APP_STATUS_INITIALIZED:
			break;
		case APP_STATUS_DEAD:
			ISOException.throwIt(Constants.SW_APPLET_DEAD);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
	}
	
	/**
	 * Manages the Security Environment: RESTORE/SET. Three different components of SE: <code>Wrap/Unwrap</code>,
	 * <code>HASH</code> and <code>DSA</code> is initialized with appropriate Algorithm.
	 * @param apdu
	 * @author Mostak, Rakeb
	 */
	private void mse(APDU apdu){
		byte[] apduBuffer = apdu.getBuffer();
		byte p1= apduBuffer[ISO7816.OFFSET_P1];
		byte p2 = apduBuffer[ISO7816.OFFSET_P2];
		
		if(p1 == P1_MSE_SET){	//set
			apdu.setIncomingAndReceive();
			byte algoRef = apduBuffer[(short)7];
			checkAPDUHeader(apdu, (byte) (CHECK_LC), (byte) 0x00, (byte) 0x00,
					(short) 0x0000, (byte) 0x03);
			
			if(Util.getShort(apduBuffer, ISO7816.OFFSET_CDATA) != (short)0x8001) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			if (d_OperationState[OFFSET_MSE] == Constants.FALSE) {
				ISOException.throwIt(Constants.SW_SE_NOT_RESTORED);
			}
			if(p2==P2_DSA){
				if((algoRef>=Constants.ALG_MIN)&&(algoRef<=Constants.DS_ALG_MAX))
					d_SecurityEnvironment[OFFSET_SE_DSA] = algoRef;
				else
					ISOException.throwIt(Constants.SW_ALG_NOT_SUPPORTED);
			}else if(p2==P2_HASH){ 
				if((algoRef>=Constants.ALG_MIN)&&((short)algoRef<=Constants.HASH_ALG_MAX))
					d_SecurityEnvironment[OFFSET_SE_HASH] = algoRef;
				else
					ISOException.throwIt(Constants.SW_ALG_NOT_SUPPORTED);
			}else if(p2==P2_CON){
				if((algoRef>=Constants.ALG_MIN)&&(algoRef<=Constants.CON_ALG_MAX))
					d_SecurityEnvironment[OFFSET_SE_CON] = algoRef;
				else
					ISOException.throwIt(Constants.SW_ALG_NOT_SUPPORTED);
			}else{
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
		}else if(p1 == P1_MSE_RESTORE){	//restore
			checkAPDUHeader(apdu, (byte) (CHECK_P2 | CHECK_LC), (byte) 0x00, (byte) 0x00,
					(short) 0x0000, (byte) 0x00);
			
			d_SecurityEnvironment[OFFSET_SE_HASH]	= ALG_SHA_256;					// MessageDigest.ALG_SHA_256
			d_SecurityEnvironment[OFFSET_SE_CON]	= ALG_AES_BLOCK_128_CBC_NOPAD;	// Cipher.ALG_AES_BLOCK_128_CBC_NOPAD ;
			d_SecurityEnvironment[OFFSET_SE_DSA]	= ALG_AES_MAC_128_NOPAD;		// Signature.ALG_AES_MAC_128_NOPAD ;
			
			d_OperationState[OFFSET_MSE] = Constants.TRUE;
		}
		else{
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
	}

	/**
	 * Initialize and Set the Key object by the key data from Key Containers.
	 * @param offsetSE
	 * @return Key
	 * @author Mostak, Rakeb
	 */
	private Key keyInit(byte offsetSE){
		Key opKey = null;
		byte algoRef;
		if(offsetSE == OFFSET_VERIFY_DS) {
			algoRef = d_SecurityEnvironment[OFFSET_SE_DSA];
		} else {
			algoRef = d_SecurityEnvironment[offsetSE];
		}
		
		short keyLen = (short)0;
		switch(offsetSE){
			case OFFSET_SE_DSA:
				keyLen = d_KeyContainers[OFFSET_CSP_DEM_MAC].c_storedLen;
				if((algoRef >= Constants.DS_ALG_AES_MIN)&&(algoRef <= Constants.DS_ALG_AES_MAX)) {
					if(d_KeyContainers[OFFSET_CSP_DEM_MAC].c_keyType != KeyBuilder.TYPE_AES){
						ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
					}
					AESKey aesKey = (AESKey) d_KeyRefs[OFFSET_KEY_AES];
					if(aesKey.getSize()!=keyLen){
						aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, keyLen, false);
						d_KeyRefs[OFFSET_KEY_AES] = aesKey;
						d_MemoryGarbage = true;
					}
					aesKey.setKey(d_KeyContainers[OFFSET_CSP_DEM_MAC].c_body, Constants.OFFSET_ZERO);
					opKey = aesKey;
				} else if((algoRef >= Constants.DS_ALG_DES_MIN) && (algoRef <= Constants.DS_ALG_DES_MAX)) {
					if(d_KeyContainers[OFFSET_CSP_DEM_MAC].c_keyType != KeyBuilder.TYPE_DES){
						ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
					}
					DESKey desKey = (DESKey) d_KeyRefs[OFFSET_KEY_DES];
					if(desKey.getSize()!=keyLen){
						desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_RESET, keyLen, false);
						d_KeyRefs[OFFSET_KEY_DES] = desKey;
						d_MemoryGarbage = true;
					}
					desKey.setKey(d_KeyContainers[OFFSET_CSP_DEM_MAC].c_body, Constants.OFFSET_ZERO);
					opKey = desKey;
				} else if((algoRef >= Constants.DS_ALG_HMAC_MIN) && (algoRef <= Constants.DS_ALG_HMAC_MAX)) {
					if(d_KeyContainers[OFFSET_CSP_DEM_MAC].c_keyType != KeyBuilder.TYPE_HMAC){
						ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
					}
					if(algoRef==Constants.DS_ALG_HMAC_MIN || algoRef==Constants.DS_ALG_HMAC_MIN+1){
						 d_KeyRefs[OFFSET_KEY_HMAC] = (HMACKey)KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT, KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
					}else{
						 d_KeyRefs[OFFSET_KEY_HMAC] = (HMACKey)KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT, KeyBuilder.LENGTH_HMAC_SHA_512_BLOCK_128, false);
					}
					d_MemoryGarbage = true;
					HMACKey hmacKey= (HMACKey)d_KeyRefs[OFFSET_KEY_HMAC];
					hmacKey.setKey(d_KeyContainers[OFFSET_CSP_DEM_MAC].c_body, Constants.OFFSET_ZERO, (short)(keyLen/8));
					opKey = hmacKey;
				}else if((algoRef>=(byte)(Constants.DS_ALG_RSA_MIN + (byte)0x04)) && (algoRef<=Constants.DS_ALG_RSA_MAX)){
					try {
						opKey = ((KeyPair) d_KeyRefs[OFFSET_KEYPAIR_DS]).getPrivate();
						if(opKey.getType()!=KeyBuilder.TYPE_RSA_PRIVATE){
							opKey=null;
							ISOException.throwIt(Constants.SW_KEY_NOT_INITIALIZE);
						}
					} catch (CryptoException e) {
						ISOException.throwIt((short) (Constants.SW_INVALID_DATA_BLOCK | e.getReason()));
					}					
				}else if((algoRef>=Constants.DS_ALG_ECDSA_MIN + (byte)0x01) && (algoRef<=Constants.DS_ALG_ECDSA_MAX)){
					try {
						opKey = ((KeyPair) d_KeyRefs[OFFSET_KEYPAIR_DS]).getPrivate();
						if(opKey.getType()!=KeyBuilder.TYPE_EC_FP_PRIVATE){
							opKey=null;
							ISOException.throwIt(Constants.SW_KEY_NOT_INITIALIZE);
						}
					} catch (CryptoException e) {
						ISOException.throwIt((short) (Constants.SW_INVALID_DATA_BLOCK | e.getReason()));
					}
				}
				else {
					ISOException.throwIt(Constants.SW_ALG_NOT_SUPPORTED);
				}
				break;
			case OFFSET_SE_CON:
				keyLen = d_KeyContainers[OFFSET_CSP_DEM_CON_SECRET].c_storedLen;
				if((algoRef >= Constants.CON_ALG_AES_MIN) && (algoRef <= Constants.CON_ALG_AES_MAX)) {
					if(d_KeyContainers[OFFSET_CSP_DEM_CON_SECRET].c_keyType != KeyBuilder.TYPE_AES){
						ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
					}
					AESKey aesKey = (AESKey) d_KeyRefs[OFFSET_KEY_AES];
					if(aesKey.getSize()!=keyLen){
						aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, keyLen, false);
						d_KeyRefs[OFFSET_KEY_AES] = aesKey;
						d_MemoryGarbage = true;
					}
					aesKey.setKey(d_KeyContainers[OFFSET_CSP_DEM_CON_SECRET].c_body, Constants.OFFSET_ZERO);
					opKey = aesKey;
				} else if((algoRef >= Constants.CON_ALG_DES_MIN) && (algoRef <= Constants.CON_ALG_DES_MAX)) {
					if(d_KeyContainers[OFFSET_CSP_DEM_CON_SECRET].c_keyType != KeyBuilder.TYPE_DES){
						ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
					}
					DESKey desKey = (DESKey) d_KeyRefs[OFFSET_KEY_DES];
					if(desKey.getSize()!=keyLen){
						desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_RESET, keyLen, false);
						d_KeyRefs[OFFSET_KEY_DES] = desKey;
						d_MemoryGarbage = true;
					}
					desKey.setKey(d_KeyContainers[OFFSET_CSP_DEM_CON_SECRET].c_body, Constants.OFFSET_ZERO);
					opKey = desKey;
				} else{
					ISOException.throwIt(Constants.SW_ALG_NOT_SUPPORTED);
				}
				break;
			case OFFSET_VERIFY_DS:
				KeyPair ecKeyPair2 = null; // for EC: keypair will act as ecKeyPair2

				if((algoRef >= Constants.DS_ALG_AES_MIN)&&(algoRef <= Constants.DS_ALG_AES_MAX)) {
					if(d_KeyContainers[OFFSET_CSP_DEM_MAC].c_keyType != KeyBuilder.TYPE_AES){
						ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
					}
					keyLen = d_KeyContainers[OFFSET_CSP_DEM_MAC].c_storedLen;
					AESKey aesKey = (AESKey) d_KeyRefs[OFFSET_KEY_AES];
					if(aesKey.getSize()!=keyLen){
						aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, keyLen, false);
						d_KeyRefs[OFFSET_KEY_AES] = aesKey;
						d_MemoryGarbage = true;
					}
					aesKey.setKey(d_KeyContainers[OFFSET_CSP_DEM_MAC].c_body, Constants.OFFSET_ZERO);
					opKey = aesKey;
				} else if((algoRef >= Constants.DS_ALG_DES_MIN) && (algoRef <= Constants.DS_ALG_DES_MAX)) {
					if(d_KeyContainers[OFFSET_CSP_DEM_MAC].c_keyType != KeyBuilder.TYPE_DES) {
						ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
					}
					keyLen = d_KeyContainers[OFFSET_CSP_DEM_MAC].c_storedLen;
					DESKey desKey = (DESKey) d_KeyRefs[OFFSET_KEY_DES];
					if(desKey.getSize()!=keyLen){
						desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_RESET, keyLen, false);
						d_KeyRefs[OFFSET_KEY_DES] = desKey;
						d_MemoryGarbage = true;
					}
					desKey.setKey(d_KeyContainers[OFFSET_CSP_DEM_MAC].c_body, Constants.OFFSET_ZERO);
					opKey = desKey;
				} else if((algoRef >= Constants.DS_ALG_HMAC_MIN) && (algoRef <= Constants.DS_ALG_HMAC_MAX)) {
					if(d_KeyContainers[OFFSET_CSP_DEM_MAC].c_keyType != KeyBuilder.TYPE_HMAC){
						ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
					}
					keyLen = d_KeyContainers[OFFSET_CSP_DEM_MAC].c_storedLen;
					HMACKey hmacKey= (HMACKey)d_KeyRefs[OFFSET_KEY_HMAC];
					hmacKey.setKey(d_KeyContainers[OFFSET_CSP_DEM_MAC].c_body, Constants.OFFSET_ZERO, (short)(keyLen/8));
					opKey = hmacKey;
				} else if((algoRef >= Constants.DS_ALG_RSA_MIN) && (algoRef <= Constants.DS_ALG_RSA_MAX)){
					if(d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_keyType != KeyBuilder.TYPE_RSA_PUBLIC) {
						ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
					}
					keyLen = d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_storedLen;
					short keySize = rsaPublicKey.getSize();
					if((keyLen < KeyBuilder.LENGTH_RSA_2048) && (keySize == KeyBuilder.LENGTH_RSA_2048)) {
						rsaPublicKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
						d_MemoryGarbage = true;
					}
					if((keyLen > KeyBuilder.LENGTH_RSA_2048) && (keySize == KeyBuilder.LENGTH_RSA_1024)) {
						rsaPublicKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
						d_MemoryGarbage = true;
					}
					if(keyLen<(short)2048){
						rsaPublicKey.setModulus(d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_body, Constants.OFFSET_ZERO, (short)128);
						rsaPublicKey.setExponent(d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_body, (short)128, (short)((short)(keyLen/8)-(short)128));
					}
					else{
						rsaPublicKey.setModulus(d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_body, Constants.OFFSET_ZERO, (short)256);
						rsaPublicKey.setExponent(d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_body, (short)256, (short)((short)(keyLen/8)-(short)256));
					}
					opKey = rsaPublicKey;
//					opKey = getDemPubKey();
				} else if((algoRef >= Constants.DS_ALG_ECDSA_MIN) && (algoRef <= Constants.DS_ALG_ECDSA_MAX)){
					keyLen = d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_storedLen;
					if((keyLen == Constants.OFFSET_ZERO) || (d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_keyType != KeyBuilder.TYPE_EC_FP_PUBLIC)) {
						ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
					}
					ecKeyPair2 = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_3P];
					switch ((short)(keyLen/8)) {
						case Constants.LENGTH_EC_192:
							if(ecKeyPair2.getPublic().getSize() != KeyBuilder.LENGTH_EC_FP_192) {
								d_KeyRefs[OFFSET_KEYPAIR_3P] = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
								ecKeyPair2 = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_3P];
								d_MemoryGarbage = true;
							}
							break;
						case Constants.LENGTH_EC_224:
							if(ecKeyPair2.getPublic().getSize() != KeyBuilder.LENGTH_EC_FP_224) {
								d_KeyRefs[OFFSET_KEYPAIR_3P] = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_224);
								ecKeyPair2 = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_3P];
								d_MemoryGarbage = true;
							}
							break;
						case Constants.LENGTH_EC_256:
							if(ecKeyPair2.getPublic().getSize() != KeyBuilder.LENGTH_EC_FP_256) {
								d_KeyRefs[OFFSET_KEYPAIR_3P] = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
								ecKeyPair2 = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_3P];
								d_MemoryGarbage = true;
							}
							break;
						case Constants.LENGTH_EC_384:
							if(ecKeyPair2.getPublic().getSize() != KeyBuilder.LENGTH_EC_FP_384) {
								d_KeyRefs[OFFSET_KEYPAIR_3P] = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_384);
								ecKeyPair2 = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_3P];
								d_MemoryGarbage = true;
							}
							break;
						case Constants.LENGTH_EC_521:
							if(ecKeyPair2.getPublic().getSize() != KeyBuilder.LENGTH_EC_FP_521) {
								d_KeyRefs[OFFSET_KEYPAIR_3P] = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_521);
								ecKeyPair2 = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_3P];
								d_MemoryGarbage = true;
							}
							break;
	
						default:
							ISOException.throwIt(Constants.SW_KEYPAIR_NOT_SUPPORTED);
							break;
					}
					ecKeyPair2.getPublic().clearKey();
					ecKeyPair2.getPrivate().clearKey();
					ecKeyPair2.genKeyPair();
					((ECPublicKey)(ecKeyPair2.getPublic())).setW(d_KeyContainers[OFFSET_CSP_DEM_3P_PUB].c_body, Constants.OFFSET_ZERO, (short)(keyLen/8));
					opKey = (ECPublicKey) ecKeyPair2.getPublic();
				}
				else {
					ISOException.throwIt(Constants.SW_ALG_NOT_SUPPORTED);
					}
				break;
			default:
				ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
				break;
		}
		if(!opKey.isInitialized()){
			ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
		}
		return opKey;
	}
	
	/**
	 * Gets the Cipher object's reference depending on the mechanism told at Security Environment's 
	 * <code>WRAP/Unwrap</code> components and return that Cipher object.
	 * @param offsetSE
	 * @return Cipher object
	 * @author Rakeb
	 */
	private Cipher getCipherInstance(byte offsetSE) {
		byte algoRef = d_SecurityEnvironment[offsetSE];
		byte algo = Constants.CON_ALGO[algoRef-(byte)0x01];
		Cipher cipher = null;
		if (algoRef >= Constants.CON_ALG_AES_CBC_MIN && algoRef <= Constants.CON_ALG_AES_CBC_MAX) {
			cipher = d_CipherRefs[OFFSET_CIPHER_AES_CBC];
			if(algo != cipher.getAlgorithm()){
				cipher = Cipher.getInstance(algo, false);
				d_CipherRefs[OFFSET_CIPHER_AES_CBC] = cipher;
				d_MemoryGarbage = true;
			}
		} else if (algoRef >= Constants.CON_ALG_AES_ECB_MIN && algoRef <= Constants.CON_ALG_AES_ECB_MAX) {
			cipher = d_CipherRefs[OFFSET_CIPHER_AES_ECB];
			if(algo != cipher.getAlgorithm()){
				cipher = Cipher.getInstance(algo, false);
				d_CipherRefs[OFFSET_CIPHER_AES_ECB]= cipher;
				d_MemoryGarbage = true;
			}
		} else if ((algoRef>=Constants.CON_ALG_DES_CBC_MIN) && (algoRef<=Constants.CON_ALG_DES_CBC_MAX)) {
			cipher = d_CipherRefs[OFFSET_CIPHER_DES_CBC];
			if(algo != cipher.getAlgorithm()){
				cipher = Cipher.getInstance(algo, false);
				d_CipherRefs[OFFSET_CIPHER_DES_CBC] = cipher;
				d_MemoryGarbage = true;
			}
		} else if ((algoRef>=Constants.CON_ALG_DES_ECB_MIN) && (algoRef<=Constants.CON_ALG_DES_ECB_MAX)) {
			cipher = d_CipherRefs[OFFSET_CIPHER_DES_ECB];
			if(algo != cipher.getAlgorithm()){
				cipher = Cipher.getInstance(algo, false);
				d_CipherRefs[OFFSET_CIPHER_DES_ECB] = cipher;
				d_MemoryGarbage = true;
			}
		} else if(algoRef ==  Constants.CON_ALG_RSA_MIN || algoRef ==  Constants.CON_ALG_MAX) {
			cipher = d_CipherRefs[OFFSET_CIPHER_RSA];	
			if(algo != cipher.getAlgorithm()){
				cipher = Cipher.getInstance(algo, false);
				d_CipherRefs[OFFSET_CIPHER_RSA] = cipher;
				d_MemoryGarbage = true;
			}
		} else
			ISOException.throwIt(Constants.SW_ALG_NOT_SUPPORTED);
		
		if((d_MemoryGarbage == true) && JCSystem.isObjectDeletionSupported()) {
			JCSystem.requestObjectDeletion();
			d_MemoryGarbage = false;
		}
		return cipher;
	}
	
	/**
	 * Perform Security Operations: <code>DS/MAC Generation/Verification</code>,
	 * <code>HASH Generation</code> and <code>WRAP/UNWRAP</code>
	 * 
	 * @param apdu
	 * 
	 * @author Rakeb, Mostak
	 * 
	 * @exception CryptoException
     *                with the following reason codes:
     *                <ul>
     *                <li><code>CryptoException.NO_SUCH_ALGORITHM</code> if
     *                the requested algorithm is not supported or shared access
     *                mode is not supported.
     *                <li><code>CryptoException.ILLEGAL_VALUE</code> if
     *                <code>theMode</code> option is an undefined value or if
     *                the <code>Key</code> is inconsistent with the
     *                <code>Cipher</code> implementation.
     *                <li><code>CryptoException.UNINITIALIZED_KEY</code> if
     *                key not initialized.
     *                <li><code>CryptoException.INVALID_INIT</code> if this
     *                <code>Cipher</code> or <code>Signature</code> object is not 
     *                initialized or initialized for signature verify mode.
     *                <li><code>CryptoException.ILLEGAL_USE</code> if one of
     *                the following conditions is met:
     *                <ul>
     *                <li>if this <code>Cipher</code>or <code>Signature</code> algorithm does not
     *                pad the message and the message is not block aligned.
     *                <li>if this <code>Cipher</code> or <code>Signature</code> algorithm does not
     *                pad the message and no input data has been provided in
     *                <code>inBuff</code> or via the <code>update()</code>
     *                method.
     *                <li>if the message value is not supported by the
     *                <code>Cipher</code> or <code>Signature</code> algorithm
     *                or if a message value consistency check failed.
     *                <li>if this <code>Signature</code> algorithm includes
     *                message recovery functionality.
     *                <li>The decrypted data is not bounded by appropriate
	 *                padding bytes.
     *                </ul>
	 */
	private void pso(APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();
		short p1p2;
		short responseLen = (short)0;

		byte algoRef= (byte)0x00;
		byte algo= (byte)0x00;
		short dataLen = (short)(0x00ff & apduBuffer[ISO7816.OFFSET_LC]);

		if(apdu.setIncomingAndReceive() != dataLen) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		p1p2 = Util.getShort(apduBuffer, ISO7816.OFFSET_P1);
		
		Key key = null;
		Cipher cipher;
		Signature sig = null;
		
		switch(p1p2){
			case P1P2_PSO_DS:
				key = keyInit(OFFSET_SE_DSA);
				algoRef = d_SecurityEnvironment[OFFSET_SE_DSA];
				algo = Constants.DS_ALGO[algoRef-(short)01];
				sig = getSignatureInstance();
				try{
					sig.init(key, Signature.MODE_SIGN);
				}catch(CryptoException e){
					ISOException.throwIt((short) ((short)0x9000|e.getReason()));
				}
				try{
					responseLen = sig.sign(apduBuffer, ISO7816.OFFSET_CDATA, dataLen, d_tempBuffer, Constants.OFFSET_ZERO);
				}catch(CryptoException e){
					ISOException.throwIt((short) (Constants.SW_INVALID_DATA_BLOCK|e.getReason()));
				}
				break;
			case P1P2_PSO_VERIFY_DS:
				/**
				 * receive sign data, tag 20, 40 and 10 means first part of sign data, last part of sign data and input
				 * message respectively
				 */
				if(apduBuffer[ISO7816.OFFSET_CDATA] == (byte)0x20) {
					d_FlagArray[OFFSET_SIGN_DATA_CHECK] = Constants.TRUE;
					d_FlagArray[OFFSET_SIGN_VERIFY_CHECK] = Constants.TRUE;
					d_tempBuffer[(short)0] = (byte)(apduBuffer[ISO7816.OFFSET_LC] - (byte)0x01);
					d_tempBuffer[(short)1] = (byte)Constants.OFFSET_ZERO; // explicit initialization
					Util.arrayCopyNonAtomic(apduBuffer, (short)((short)ISO7816.OFFSET_CDATA +(short)1), d_tempBuffer, (short)2, (short)(dataLen - (short)1));
					d_OperationState[OFFSET_STATE] = Constants.STATE_SIGN_VERIFY;
					ISOException.throwIt(ISO7816.SW_NO_ERROR);
				} else if ((apduBuffer[ISO7816.OFFSET_CDATA] == (byte)0x40) && d_FlagArray[OFFSET_SIGN_DATA_CHECK] == Constants.TRUE) {
					d_FlagArray[OFFSET_SIGN_DATA_CHECK] = Constants.FALSE;
					d_tempBuffer[(short)1] = (byte)(apduBuffer[ISO7816.OFFSET_LC] - (byte)0x01);
					Util.arrayCopyNonAtomic(apduBuffer, (short)((short)ISO7816.OFFSET_CDATA +(short)1), d_tempBuffer, (short)((short)2 + (short)(0x00ff & d_tempBuffer[0])), (short)(dataLen - (short)1));
					ISOException.throwIt(ISO7816.SW_NO_ERROR);
				} else if ((apduBuffer[ISO7816.OFFSET_CDATA] == (byte)0x10) && d_FlagArray[OFFSET_SIGN_VERIFY_CHECK] == Constants.TRUE) {
					// do nothing
				} else {
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				}
				
				key = keyInit(OFFSET_VERIFY_DS);
				/**
				 * get signature instance
				 */
				algoRef = d_SecurityEnvironment[OFFSET_SE_DSA];
				algo = Constants.DS_ALGO[algoRef-(short)01];
				sig = getSignatureInstance();
//				if(algoRef==Constants.DS_ALG_AES_MIN){	// ALG_AES
//					sig.init(key, Signature.MODE_SIGN);
//					short macLen = sig.sign(apduBuffer, (short)((short)ISO7816.OFFSET_CDATA +(short)1), (short)(dataLen-(short)1), d_tempBuffer, Constants.BLOCK_SIZE_32);
//					if(Util.arrayCompare(d_tempBuffer, (short)2, d_tempBuffer, Constants.BLOCK_SIZE_32, macLen)!=(byte)0x00){
//						ISOException.throwIt(Constants.SW_SIGNATURE_VERIFICATION_FAILED);
//					}else{
//						ISOException.throwIt(ISO7816.SW_NO_ERROR);
//					}
//				}
				try {
					sig.init(key, Signature.MODE_VERIFY);
					short sigLength = (short)((short)((short)d_tempBuffer[0] & 0x00ff) + (short)((short)d_tempBuffer[1] & 0x00ff));
					if(!sig.verify(apduBuffer, (short)((short)ISO7816.OFFSET_CDATA +(short)1), (short)(dataLen-(short)1), d_tempBuffer, (short)2, sigLength)){
						ISOException.throwIt(Constants.SW_SIGNATURE_VERIFICATION_FAILED);
					}
				}
				catch(CryptoException e){
					ISOException.throwIt((short) (Constants.SW_INVALID_DATA_BLOCK | e.getReason()));
				}
				d_OperationState[OFFSET_STATE] = Constants.STATE_AUTHENTICATE_IDLE;
				d_FlagArray[OFFSET_SIGN_DATA_CHECK] = Constants.FALSE;
				d_FlagArray[OFFSET_SIGN_VERIFY_CHECK] = Constants.FALSE;
				break;
				
			case P1P2_PSO_HASH:
				algoRef = d_SecurityEnvironment[OFFSET_SE_HASH];
				algo = Constants.HASH_ALGO[algoRef-(byte)0x01];
				MessageDigest md = null;
				if(algoRef >= Constants.HASH_ALG_SHA1_MIN && algoRef <= Constants.HASH_ALG_SHA1_MAX){
					md = d_DigestRefs[OFFSET_DIGEST_SHA1];
					if(algo != md.getAlgorithm()){
						d_DigestRefs[OFFSET_DIGEST_SHA1] = MessageDigest.getInstance(algo, false);
						md = d_DigestRefs[OFFSET_DIGEST_SHA1];
						if(JCSystem.isObjectDeletionSupported()) {
							JCSystem.requestObjectDeletion();
						}
					}
				}else if((algoRef>=Constants.HASH_ALG_SHA2_MIN)&&(algoRef<=Constants.HASH_ALG_SHA2_MAX)){
					md = d_DigestRefs[OFFSET_DIGEST_SHA2];
					if(algo!=md.getAlgorithm()){
						d_DigestRefs[OFFSET_DIGEST_SHA2] = MessageDigest.getInstance(algo, false);
						md = d_DigestRefs[OFFSET_DIGEST_SHA2];
						if(JCSystem.isObjectDeletionSupported()) {
							JCSystem.requestObjectDeletion();
						}
					}
				}else{
					ISOException.throwIt(Constants.SW_ALG_NOT_SUPPORTED);
				}
				
				responseLen = md.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, dataLen, d_tempBuffer, Constants.OFFSET_ZERO);
				break;
			
			case P1P2_PSO_ENC:
				if(dataLen>=Constants.BLOCK_SIZE_240){
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				key 	= keyInit(OFFSET_SE_CON);
				cipher	= getCipherInstance(OFFSET_SE_CON);
				try {
					cipher.init(key, Cipher.MODE_ENCRYPT);
					responseLen = cipher.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, dataLen, d_tempBuffer, Constants.OFFSET_ZERO);
				} catch(CryptoException e){
					ISOException.throwIt((short) (Constants.SW_INVALID_DATA_BLOCK | e.getReason()));
				}
				break;
			
			case P1P2_PSO_DEC:
				if(dataLen>Constants.BLOCK_SIZE_240){
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				key 	= keyInit(OFFSET_SE_CON);
				cipher	= getCipherInstance(OFFSET_SE_CON);
				try {
					cipher.init(key, Cipher.MODE_DECRYPT);
					responseLen = cipher.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, dataLen, d_tempBuffer, Constants.OFFSET_ZERO);
				} catch(CryptoException e){
					ISOException.throwIt((short) (Constants.SW_INVALID_DATA_BLOCK | e.getReason()));
				}
				break;
			default:
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}		
		apdu.setOutgoing();
		apdu.setOutgoingLength(responseLen);
		apdu.sendBytesLong(d_tempBuffer, Constants.OFFSET_ZERO, responseLen);
	}

	/**
	 * Generates <code>RSA</code> and <code>EC</code> key pair.
	 * @param apdu
	 * @author Mostak Ahmed
	 */
	private void generateKeyPair(APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();
		checkAPDUHeader(apdu, (byte)(CHECK_P1P2 | CHECK_LC), (byte)0x00, (byte)0x00, (short)0x0000, (byte)0x01);
		
		KeyPair keypair = null;
		apdu.setIncomingAndReceive();
		byte data = apduBuffer[ISO7816.OFFSET_CDATA];
		switch((data &(byte)0xf0)){
			case GENERATE_KEYPAIR_RSA:
				switch(data){
					case GENERATE_KEYPAIR_RSA_2048_SIGN:
						keypair = getKeyPairRef(GENERATE_KEYPAIR_RSA_2048_SIGN, KeyBuilder.LENGTH_RSA_2048);
						break;
					case GENERATE_KEYPAIR_RSA_CRT_2048_SIGN:
						keypair = getKeyPairRef(GENERATE_KEYPAIR_RSA_CRT_2048_SIGN, KeyBuilder.LENGTH_RSA_2048);
						break;
					case GENERATE_KEYPAIR_RSA_2048_CON:
						keypair = getKeyPairRef(GENERATE_KEYPAIR_RSA_2048_CON, KeyBuilder.LENGTH_RSA_2048);
						break;
					case GENERATE_KEYPAIR_RSA_CRT_2048_CON:
						keypair = getKeyPairRef(GENERATE_KEYPAIR_RSA_CRT_2048_CON, KeyBuilder.LENGTH_RSA_2048);
						break;
					default:
						ISOException.throwIt(Constants.SW_KEYPAIR_NOT_SUPPORTED);
				}
				break;
			case GENERATE_KEYPAIR_ECP:
				switch(data){
					case GENERATE_KEYPAIR_ECP_224:
						keypair = getKeyPairRef(GENERATE_KEYPAIR_ECP, KeyBuilder.LENGTH_EC_FP_224);
						break;
					case GENERATE_KEYPAIR_ECP_256:
						keypair = getKeyPairRef(GENERATE_KEYPAIR_ECP, KeyBuilder.LENGTH_EC_FP_256);
						break;
					case GENERATE_KEYPAIR_ECP_384:
						keypair = getKeyPairRef(GENERATE_KEYPAIR_ECP, KeyBuilder.LENGTH_EC_FP_384);
						break;
					case GENERATE_KEYPAIR_ECP_521:
						keypair = getKeyPairRef(GENERATE_KEYPAIR_ECP, KeyBuilder.LENGTH_EC_FP_521);
						break;
					default:
						ISOException.throwIt(Constants.SW_KEYPAIR_NOT_SUPPORTED);
				}
				break;
			default:
				ISOException.throwIt(Constants.SW_KEYPAIR_NOT_SUPPORTED);
		}
		keypair.getPublic().clearKey();
		keypair.getPrivate().clearKey();
		keypair.genKeyPair();
	}
	
	/**
	 * Gets the KeyPair Reference of the given type and key length.
	 * @param type <code>RSA</code> or <code>EC</code>
	 * @param keyLen
	 * @return {@link KeyPair}
	 * @author Mostak Ahmed
	 */
	private KeyPair getKeyPairRef(byte type, short keyLen){
		KeyPair keyPair = null;
		switch(type){
			case GENERATE_KEYPAIR_RSA_2048_SIGN:
				keyPair = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_DS];
				if(keyPair.getPrivate().getType()!= KeyBuilder.TYPE_RSA_PRIVATE){
					d_KeyRefs[OFFSET_KEYPAIR_DS] = new KeyPair(KeyPair.ALG_RSA, keyLen);
					keyPair = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_DS];
					d_MemoryGarbage = true;
				}
				break;
			case GENERATE_KEYPAIR_RSA_CRT_2048_SIGN:
				keyPair = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_DS];
				if(keyPair.getPrivate().getType()!= KeyBuilder.TYPE_RSA_CRT_PRIVATE){
					d_KeyRefs[OFFSET_KEYPAIR_DS] = new KeyPair(KeyPair.ALG_RSA_CRT, keyLen);
					keyPair = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_DS];
					d_MemoryGarbage = true;
				}
				break;
			case GENERATE_KEYPAIR_RSA_2048_CON:
				keyPair = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_RSA_WRAP];
				if(keyPair.getPrivate().getType()!= KeyBuilder.TYPE_RSA_PRIVATE){
					d_KeyRefs[OFFSET_KEYPAIR_RSA_WRAP] = new KeyPair(KeyPair.ALG_RSA, keyLen);
					keyPair = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_RSA_WRAP];
					d_MemoryGarbage = true;
				}
				break;
			case GENERATE_KEYPAIR_RSA_CRT_2048_CON:
				keyPair = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_RSA_WRAP];
				if(keyPair.getPrivate().getType()!= KeyBuilder.TYPE_RSA_CRT_PRIVATE){
					d_KeyRefs[OFFSET_KEYPAIR_RSA_WRAP] = new KeyPair(KeyPair.ALG_RSA_CRT, keyLen);
					keyPair = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_RSA_WRAP];
					d_MemoryGarbage = true;
				}
				break;
			case GENERATE_KEYPAIR_ECP:
				keyPair = (KeyPair)d_KeyRefs[OFFSET_KEYPAIR_DS];
				if(keyPair.getPublic().getType()==KeyBuilder.TYPE_EC_FP_PUBLIC){
					if(((ECPublicKey)keyPair.getPublic()).getSize()!=keyLen){
							d_KeyRefs[OFFSET_KEYPAIR_DS] = new KeyPair(KeyPair.ALG_EC_FP, keyLen);
							keyPair = (KeyPair)d_KeyRefs[OFFSET_KEYPAIR_DS];
							d_MemoryGarbage = true;
					}
				}else{
					d_KeyRefs[OFFSET_KEYPAIR_DS] = new KeyPair(KeyPair.ALG_EC_FP, keyLen);
					keyPair = (KeyPair)d_KeyRefs[OFFSET_KEYPAIR_DS];
					d_MemoryGarbage = true;
				}
				break;
			default:
				ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
		}
		return keyPair;
	}
	
	/**
	 * Checks the apdu header for requested command.
	 * 
	 * @param apdu
	 * @param checkByte
	 * @param P1
	 * @param P2
	 * @param P1P2
	 * @param Lc
	 * @author Mostak Ahmed
	 */
	private void checkAPDUHeader(APDU apdu, byte checkByte, byte P1, byte P2, short P1P2, byte Lc) {
		byte[] apduBuffer = apdu.getBuffer();
		byte p1 = apduBuffer[ISO7816.OFFSET_P1];
		byte p2 = apduBuffer[ISO7816.OFFSET_P2];
		short p1p2 = Util.getShort(apduBuffer, ISO7816.OFFSET_P1);
		byte lc = apduBuffer[ISO7816.OFFSET_LC]; 
		
		//check parameter byte p1
		if(((checkByte & CHECK_P1) != (byte)0x00) && (p1 != P1)) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		//check parameter byte p2
		if(((checkByte & CHECK_P2) != (byte)0x00) && (p2 != P2)) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		//check parameters word p1p2
		if(((checkByte & CHECK_P1P2) != (byte)0x00) && (p1p2 != P1P2)) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		//check data length byte lc
		if(((checkByte & CHECK_LC) != (byte)0x00) && (lc != Lc)) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
	}
	
	/**
	 * Checks the Operation state for requested command.
	 * 
	 * @param apdu
	 * @author Mostak, Rakeb
	 */
	private void checkOperationState(APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();
		byte insByte = apduBuffer[ISO7816.OFFSET_INS];
		byte p2 = apduBuffer[ISO7816.OFFSET_P2];
		switch(d_OperationState[OFFSET_STATE]){
			case Constants.STATE_IDLE:
				switch(insByte) {
					case INS_SELECT_APPLET:
					case INS_INITIALIZE_UPDATE:
						break;
					case INS_GET_DATA:
						if(p2 != GET_OPERATION_STATE && p2 != GET_APPLET_INFO)
							ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
						break;
					default:
						ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}	
				break;
			case Constants.STATE_AUTHENTICATE:
				switch(insByte) {
					case INS_SELECT_APPLET:
					case INS_INITIALIZE_UPDATE:
					case INS_EXTERNAL_AUTHENTICATION:
						break;
					case INS_GET_DATA:
						if(p2 != GET_OPERATION_STATE && p2 != GET_APPLET_INFO)
							ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
						break;
					default:
						ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}
				break;
			case Constants.STATE_AUTHENTICATE_IDLE:
				switch(insByte) {
					case INS_EXTERNAL_AUTHENTICATION:
						ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
					default:
						break;
				}
				break;
			case Constants.STATE_PUT_DATA:
				switch(insByte) {
					case INS_EXTERNAL_AUTHENTICATION:
						ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
					case INS_GET_DATA:
						if(p2 == GET_OPERATION_STATE || p2 == GET_APPLET_INFO)
							break;
						d_FlagArray[OFFSET_1024_MODULUS_CHECKED] = Constants.FALSE;
						d_FlagArray[OFFSET_2048_MODULUS_CHECKED] = Constants.FALSE;
						d_OperationState[OFFSET_STATE] = Constants.STATE_AUTHENTICATE_IDLE;
						break;
						
					case INS_PUT_DATA:
						if((apduBuffer[ISO7816.OFFSET_P2] == P2_DEM_PUB_RSA_1024_EXP)||(apduBuffer[ISO7816.OFFSET_P2] == P2_DEM_PUB_RSA_2048_EXP)||(apduBuffer[ISO7816.OFFSET_P2] == P2_DEM_PUB_RSA_2048_MOD))
							break;						
					default:
						d_FlagArray[OFFSET_1024_MODULUS_CHECKED] = Constants.FALSE;
						d_FlagArray[OFFSET_2048_MODULUS_CHECKED] = Constants.FALSE;
						d_OperationState[OFFSET_STATE] = Constants.STATE_AUTHENTICATE_IDLE;
				}
				break;
			case Constants.STATE_SIGN_VERIFY:
				switch(insByte) {
				case INS_EXTERNAL_AUTHENTICATION:
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				case INS_GET_DATA:
					if(p2 == GET_OPERATION_STATE || p2 == GET_APPLET_INFO)
						break;
					d_FlagArray[OFFSET_SIGN_DATA_CHECK] = Constants.FALSE;
					d_FlagArray[OFFSET_SIGN_VERIFY_CHECK] = Constants.FALSE;
					d_OperationState[OFFSET_STATE] = Constants.STATE_AUTHENTICATE_IDLE;
					break;
				case INS_PSO:
					if(apduBuffer[ISO7816.OFFSET_P1] == (byte)0x00 && apduBuffer[ISO7816.OFFSET_P2] == (byte)0xA8) {
						break;
					}
				default:
					d_FlagArray[OFFSET_SIGN_DATA_CHECK] = Constants.FALSE;
					d_FlagArray[OFFSET_SIGN_VERIFY_CHECK] = Constants.FALSE;
					d_OperationState[OFFSET_STATE] = Constants.STATE_AUTHENTICATE_IDLE;
			}
				break;
			default :
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
	}
	
	/**
	 * Generates shared secret using the EC curve point and the given EC public key.
	 * <p>The APDU commands P2 defines the EC Curve point and data field contains the public key.
	 * @param apdu
	 * @author Rakeb
	 */
	private void keyAgreement(APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();
		byte p1 = apduBuffer[ISO7816.OFFSET_P1];
		byte p2 = apduBuffer[ISO7816.OFFSET_P2];
		if(p2 != (byte)0x00) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		short dataLen = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0x00FF);
		
		if(dataLen != apdu.setIncomingAndReceive()) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		/**
		 * Generate ecKeyPair1
		 */
		KeyPair ecKeyPair1 = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_3P];
		switch(p1){
		case GENERATE_KEYPAIR_ECP_224:
			if(dataLen != Constants.LENGTH_EC_224) {
				ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
			}
			if(ecKeyPair1.getPublic().getSize() != KeyBuilder.LENGTH_EC_FP_224) {
				d_KeyRefs[OFFSET_KEYPAIR_3P] = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_224);
				ecKeyPair1 = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_3P];
				d_MemoryGarbage = true;
			}
			break;
		case GENERATE_KEYPAIR_ECP_256:
			if(dataLen != Constants.LENGTH_EC_256) {
				ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
			}
			if(ecKeyPair1.getPublic().getSize() != KeyBuilder.LENGTH_EC_FP_256) {
				d_KeyRefs[OFFSET_KEYPAIR_3P] = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
				ecKeyPair1 = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_3P];
				d_MemoryGarbage = true;
			}
			break;
		case GENERATE_KEYPAIR_ECP_384:
			if(dataLen != Constants.LENGTH_EC_384) {
				ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
			}
			if(ecKeyPair1.getPublic().getSize() != KeyBuilder.LENGTH_EC_FP_384) {
				d_KeyRefs[OFFSET_KEYPAIR_3P] = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_384);
				ecKeyPair1 = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_3P];
				d_MemoryGarbage = true;
			}
			break;
		case GENERATE_KEYPAIR_ECP_521:
			if(dataLen != Constants.LENGTH_EC_521) {
				ISOException.throwIt(Constants.SW_KEY_INITIALIZATION_FAILED);
			}
			if(ecKeyPair1.getPublic().getSize() != KeyBuilder.LENGTH_EC_FP_521) {
				d_KeyRefs[OFFSET_KEYPAIR_3P] = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_521);
				ecKeyPair1 = (KeyPair) d_KeyRefs[OFFSET_KEYPAIR_3P];
				d_MemoryGarbage = true;
			}
			break;
		default:
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
		ecKeyPair1.genKeyPair();
		
		ECPublicKey ecPublicKey1 = (ECPublicKey) ecKeyPair1.getPublic();
		short wLen = ecPublicKey1.getW(d_tempBuffer, Constants.OFFSET_ZERO);

		
		
		/**
		 * create secret using ecPrivateKey1 and apduBuffer's public data
		 */
		ECPrivateKey ecPrivateKey1 	= (ECPrivateKey) ecKeyPair1.getPrivate();
		
		d_keyAgreement.init(ecPrivateKey1);
		
		//may be modify! the secret is saved in d_temBuffer from (wLen+3) to secretLen!
		try{
//			secretLen = d_keyAgreement.generateSecret(apduBuffer, (short)ISO7816.OFFSET_CDATA, dataLen, d_tempBuffer, (short) (wLen + 3));
			d_keyAgreement.generateSecret(apduBuffer, (short)ISO7816.OFFSET_CDATA, dataLen, d_shareSecretCSP, Constants.OFFSET_ZERO);
			isShareSecret = true;
		}catch(CryptoException e){
			ISOException.throwIt((short) (Constants.SW_INVALID_DATA_BLOCK|e.getReason()));
		}
		
		//clear ec key
		ecKeyPair1.getPublic().clearKey();
		ecKeyPair1.getPrivate().clearKey();
		
//		wLen = 256;
		apdu.setOutgoing();
		apdu.setOutgoingLength(wLen); 
		apdu.sendBytesLong(d_tempBuffer, Constants.OFFSET_ZERO, wLen);
		
		if((d_MemoryGarbage == true) && JCSystem.isObjectDeletionSupported()) {
			JCSystem.requestObjectDeletion();
			d_MemoryGarbage = false;
		}
	}
	
	/**
	 * Destroy DemoApplet's all CSPs, zeroise all key containers except some containers as they 
	 * restored with constant values, like <code>DEM_AUTH_KEY</code>, <code>DEM_WRAP_KEY</code> containers
	 * and clears all key objects.
	 * @param apdu
	 * @author Rakeb
	 */
	 private void destroy() {
		 PrivateKey privateKey;
		 /**
		  * destroy all CSP's KeyContainer object
		  */
		 JCSystem.beginTransaction();
		 //AUTH
		 Util.arrayCopyNonAtomic(Constants.BASE_AUTH_KEY, Constants.OFFSET_ZERO, d_KeyContainers[OFFSET_CSP_DEM_AUTH].c_body, Constants.OFFSET_ZERO, Constants.BLOCK_SIZE_16);
		 Util.arrayFillNonAtomic(d_sCounterSCP03, Constants.OFFSET_ZERO, (short)3, (byte)0x00);

		 //MAC
		 Util.arrayFillNonAtomic(d_KeyContainers[OFFSET_CSP_DEM_MAC].c_body, Constants.OFFSET_ZERO, Constants.CSP_DEM_MAC_KEY_MAX_LEN, (byte) 0x00);
		 d_KeyContainers[OFFSET_CSP_DEM_MAC].c_keyType = (byte) 0x00;
		 d_KeyContainers[OFFSET_CSP_DEM_MAC].c_storedLen = Constants.OFFSET_ZERO;

		 //WRAP
		 Util.arrayCopyNonAtomic(Constants.BASE_WRAP_KEY, Constants.OFFSET_ZERO, d_KeyContainers[OFFSET_CSP_DEM_KEY_WRAP].c_body, Constants.OFFSET_ZERO, Constants.BLOCK_SIZE_32); 
		 
		 //CON SECRET
		 Util.arrayFillNonAtomic(d_KeyContainers[OFFSET_CSP_DEM_CON_SECRET].c_body, Constants.OFFSET_ZERO, Constants.CSP_DEM_CON_SECRET_MAX_LEN, (byte) 0x00); 
		 d_KeyContainers[OFFSET_CSP_DEM_CON_SECRET].c_keyType = (byte) 0x00;
		 d_KeyContainers[OFFSET_CSP_DEM_CON_SECRET].c_storedLen = Constants.OFFSET_ZERO;
		 
		 //SHARE SECRET
		 Util.arrayFillNonAtomic(d_shareSecretCSP, Constants.OFFSET_ZERO, (short) d_shareSecretCSP.length, (byte)0x00);
		 isShareSecret = false;

		 /**
		  * destroy all keyRef object
		  */
		 if(((AESKey)d_KeyRefs[OFFSET_KEY_AES]).isInitialized()) {
			 ((AESKey)d_KeyRefs[OFFSET_KEY_AES]).clearKey();
		 }
		 if (((DESKey)d_KeyRefs[OFFSET_KEY_DES]).isInitialized()) {
			 ((DESKey)d_KeyRefs[OFFSET_KEY_DES]).clearKey();
		 }
		 if (((HMACKey)d_KeyRefs[OFFSET_KEY_HMAC]).isInitialized()) {
			 ((HMACKey)d_KeyRefs[OFFSET_KEY_HMAC]).clearKey();
		 }
		 
		 privateKey = ((KeyPair)d_KeyRefs[OFFSET_KEYPAIR_DS]).getPrivate();
		 if (privateKey.isInitialized()) {
			 privateKey.clearKey();
		 }
		 
		 privateKey = ((KeyPair)d_KeyRefs[OFFSET_KEYPAIR_3P]).getPrivate();
		 if (privateKey.isInitialized()) {
			 privateKey.clearKey();
		 }
		 
		 privateKey = ((KeyPair)d_KeyRefs[OFFSET_KEYPAIR_RSA_WRAP]).getPrivate();
		 if (privateKey.isInitialized()) {
			 privateKey.clearKey();
		 }
		 
		 random = null;
		 
		 JCSystem.commitTransaction();
	 }
	
	/**
	 * Gets the Signature object's reference depending on the mechanism told at Security Environment's 
	 * <code>DSA</code> components and return that Signature object.
	 * @return Signature object
	 * @author Mostak, Rakeb
	 */
	private Signature getSignatureInstance(){
		Signature signature = null;
		byte algoRef = d_SecurityEnvironment[OFFSET_SE_DSA];
		byte algo = Constants.DS_ALGO[algoRef-(short)01];
		if((algoRef >= Constants.DS_ALG_AES_MIN)&&(algoRef <= Constants.DS_ALG_AES_MAX)) {
			signature = d_SignatureRefs[OFFSET_SIGN_MAC_AES];
			if(algo != signature.getAlgorithm()){
				d_SignatureRefs[OFFSET_SIGN_MAC_AES] = Signature.getInstance(algo, false);
				signature = d_SignatureRefs[OFFSET_SIGN_MAC_AES];
				d_MemoryGarbage = true;
			}
		}else if((algoRef>=Constants.DS_ALG_DES_MIN) && (algoRef<=Constants.DS_ALG_DES_MAX)){				// ALG_DES_*
			signature = d_SignatureRefs[OFFSET_SIGN_MAC_3DES];
			if(algo != signature.getAlgorithm()){
				d_SignatureRefs[OFFSET_SIGN_MAC_3DES] = Signature.getInstance(algo, false);
				signature = d_SignatureRefs[OFFSET_SIGN_MAC_3DES];
				d_MemoryGarbage = true;
			}
		}else if((algoRef>=Constants.DS_ALG_HMAC_MIN) && (algoRef<=Constants.DS_ALG_HMAC_MAX)){				// ALG_HMAC_*
			signature = d_SignatureRefs[OFFSET_SIGN_MAC_HMAC];
			if(algo != signature.getAlgorithm()){
				signature = Signature.getInstance(algo, false);
				d_SignatureRefs[OFFSET_SIGN_MAC_HMAC] = signature;
				d_MemoryGarbage = true;
			}
		}else if((algoRef>=Constants.DS_ALG_RSA_MIN) && (algoRef<=Constants.DS_ALG_RSA_MAX)){				// ALG_RSA_*
			signature = d_SignatureRefs[OFFSET_SIGN_RSA];
			if(algo != signature.getAlgorithm()){
				d_SignatureRefs[OFFSET_SIGN_RSA] = Signature.getInstance(algo, false);
				signature = d_SignatureRefs[OFFSET_SIGN_RSA];
				d_MemoryGarbage = true;
			}
		}else if(algoRef>=Constants.DS_ALG_ECDSA_MIN && (algoRef<=Constants.DS_ALG_ECDSA_MAX)){		// ALG_EC_*
			signature = d_SignatureRefs[OFFSET_SIGN_EC];
			if(algo != signature.getAlgorithm()){
				d_SignatureRefs[OFFSET_SIGN_EC] = Signature.getInstance(algo, false);
				signature = d_SignatureRefs[OFFSET_SIGN_EC];
				d_MemoryGarbage = true;
			}
		} else{
			ISOException.throwIt(Constants.SW_ALG_NOT_SUPPORTED);
		}
		
		if((d_MemoryGarbage == true) && JCSystem.isObjectDeletionSupported()) {
			JCSystem.requestObjectDeletion();
			d_MemoryGarbage = false;
		}
		return signature;
	}
	
	/**

	 * This method processes the INITIALIZE_UPDATE command for SCP03.
	 * @param apdu
	 * @author Mostak Ahmed
	 */
	private void initializeUpdateSCP03(APDU apdu){
		apdu.setIncomingAndReceive();
		checkAPDUHeader(apdu, (byte)(CHECK_P1 | CHECK_P2| CHECK_LC), (byte)0x00, (byte)0x00, (short)0x0000, (byte)0x08);
		if(d_sCounterSCP03[2]!=(byte)0xFF){
			d_sCounterSCP03[2] += (byte)0x01;
		}else if(d_sCounterSCP03[1]!=(byte)0xFF){
			d_sCounterSCP03[1] += (byte)0x01;
			d_sCounterSCP03[2] = (byte)0x00;
		}else if(d_sCounterSCP03[0]!=(byte)0xFF){
			d_sCounterSCP03[0] += (byte)0x01;
			d_sCounterSCP03[1] = (byte)0x00;
			d_sCounterSCP03[2] = (byte)0x00;
		}else{
			d_appletStatus = APP_STATUS_DEAD;
			ISOException.throwIt(Constants.SW_APPLET_DEAD);
		}
		
		if(((AESKey)d_KeyRefs[OFFSET_KEY_AES]).getSize()!=KeyBuilder.LENGTH_AES_128){
			d_KeyRefs[OFFSET_KEY_AES]= (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
			d_MemoryGarbage = true;
		}
		
		if(d_SignatureRefs[OFFSET_SIGN_MAC_AES].getAlgorithm()!=Signature.ALG_AES_CMAC_128){
			d_SignatureRefs[OFFSET_SIGN_MAC_AES] = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
			d_MemoryGarbage = true;
		}
		
		if((d_MemoryGarbage == true) && JCSystem.isObjectDeletionSupported()) {
			JCSystem.requestObjectDeletion();
			d_MemoryGarbage = false;
		}
		
		((AESKey)d_KeyRefs[OFFSET_KEY_AES]).setKey(d_KeyContainers[OFFSET_CSP_DEM_AUTH].c_body, Constants.OFFSET_ZERO);
		d_SignatureRefs[OFFSET_SIGN_MAC_AES].init((AESKey)d_KeyRefs[OFFSET_KEY_AES], Signature.MODE_SIGN);
		calculateCardChallenge(Constants.AID, (short)11);
		createSessionKey(apdu);
		
		((AESKey)d_KeyRefs[OFFSET_KEY_AES]).setKey(d_cMACSessionKey, Constants.OFFSET_ZERO);
		d_SignatureRefs[OFFSET_SIGN_MAC_AES].init((AESKey)d_KeyRefs[OFFSET_KEY_AES], Signature.MODE_SIGN);
		calculateCardCryptogram(apdu);
		
		//Sequence Counter
		Util.arrayCopyNonAtomic(d_sCounterSCP03, Constants.OFFSET_ZERO, d_tempBuffer, (short) 29, (short)3);
		
		//Card Cryptogram
		Util.arrayCopyNonAtomic(d_tempBuffer, Constants.OFFSET_ZERO, d_tempBuffer, (short) 21, Constants.BLOCK_SIZE_08);
		
		//Card Challenge
		Util.arrayCopyNonAtomic(d_CardChallenge, Constants.OFFSET_ZERO, d_tempBuffer, (short) 13, Constants.BLOCK_SIZE_08);
		
		//Key Information
		d_tempBuffer[10] = (byte)0x00;		//Key Version Number
		d_tempBuffer[11] = (byte)0x03;		//Secure Channel Protocol Identifier
		d_tempBuffer[12] = (byte)0x10;		//Secure Channel Protocol
		
		//Key Diversification Data
		Util.arrayFillNonAtomic(d_tempBuffer, Constants.OFFSET_ZERO, (short)10, (byte)0x00);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength(Constants.BLOCK_SIZE_32);
		apdu.sendBytesLong(d_tempBuffer, Constants.OFFSET_ZERO, Constants.BLOCK_SIZE_32);
		
		d_OperationState[OFFSET_STATE] = Constants.STATE_AUTHENTICATE;
	}
	
	/**
	 * This method processes the EXTERNAL_AUTHENTICATE command for SCP03.
	 * @param apdu
	 * @author Mostak Ahmed
	 */
	private void externalAuthenticateSCP03(APDU apdu){
		byte[] apduBuffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		Util.arrayFillNonAtomic(d_tempBuffer, Constants.OFFSET_ZERO, Constants.BLOCK_SIZE_16, (byte)0x00);
		d_tempBuffer[(short)16]= (byte)apduBuffer[ISO7816.OFFSET_CLA];			// CLA
		d_tempBuffer[(short)17]= (byte)apduBuffer[ISO7816.OFFSET_INS];			// INS
		d_tempBuffer[(short)18]= (byte)apduBuffer[ISO7816.OFFSET_P1];			// P1
		d_tempBuffer[(short)19]= (byte)apduBuffer[ISO7816.OFFSET_P2];			// P2

		d_tempBuffer[(short)20]= (byte)apduBuffer[ISO7816.OFFSET_LC];			// Lc
		
		Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, d_tempBuffer, (short)21, Constants.BLOCK_SIZE_08);
		
		d_SignatureRefs[OFFSET_SIGN_MAC_AES].init((AESKey)d_KeyRefs[OFFSET_KEY_AES], Signature.MODE_SIGN);
		d_SignatureRefs[OFFSET_SIGN_MAC_AES].sign(d_tempBuffer, Constants.OFFSET_ZERO, (short)29, d_tempBuffer, Constants.OFFSET_ZERO);
		if(Util.arrayCompare(apduBuffer, (short)13, d_tempBuffer, Constants.OFFSET_ZERO, Constants.BLOCK_SIZE_08)!=(byte)0x00){
			d_OperationState[OFFSET_STATE] = Constants.STATE_IDLE;
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		
		//sate
		d_OperationState[OFFSET_STATE] = Constants.STATE_AUTHENTICATE_IDLE;
	}
	
	/**
	 * This method create session key for establish secure channel.
	 * @param apdu
	 * @author Mostak Ahmed
	 */
	private void createSessionKey(APDU apdu){
		byte[] apduBuffer = apdu.getBuffer();
		Util.arrayFillNonAtomic(d_tempBuffer, Constants.OFFSET_ZERO, (short)11, (byte)0x00);
		d_tempBuffer[11] = (byte)0x06;	//Derivation Constant : S-MAC
		d_tempBuffer[12] = (byte)0x00;	//Separator
		d_tempBuffer[13] = (byte)0x00;	//MSB length
		d_tempBuffer[14] = (byte)0x80;	//LSB length
		d_tempBuffer[15] = (byte)0x01;	//Counter
		
		Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, d_tempBuffer, Constants.BLOCK_SIZE_16, Constants.BLOCK_SIZE_08);
		Util.arrayCopyNonAtomic(d_CardChallenge, Constants.OFFSET_ZERO, d_tempBuffer, Constants.BLOCK_SIZE_24, Constants.BLOCK_SIZE_08);
		
		d_SignatureRefs[OFFSET_SIGN_MAC_AES].sign(d_tempBuffer, Constants.OFFSET_ZERO, Constants.BLOCK_SIZE_32, d_tempBuffer, Constants.OFFSET_ZERO);
		Util.arrayCopyNonAtomic(d_tempBuffer, Constants.OFFSET_ZERO, d_cMACSessionKey, Constants.OFFSET_ZERO, Constants.BLOCK_SIZE_16);
	}
	
	/**
	 * This method calculate card cryptogram using session key.
	 * @param apdu
	 * @author Mostak Ahmed
	 */
	private void calculateCardCryptogram(APDU apdu){
		byte[] apduBuffer = apdu.getBuffer();
		Util.arrayFillNonAtomic(d_tempBuffer, Constants.OFFSET_ZERO, (short)11, (byte)0x00);
		d_tempBuffer[11] = (byte)0x00;	//Derivation Constant : Card Cryptogram
		d_tempBuffer[12] = (byte)0x00;	//Separator
		d_tempBuffer[13] = (byte)0x00;	//MSB length
		d_tempBuffer[14] = (byte)0x40;	//LSB length
		d_tempBuffer[15] = (byte)0x01;	//Counter
		
		Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, d_tempBuffer, Constants.BLOCK_SIZE_16, Constants.BLOCK_SIZE_08);
		Util.arrayCopyNonAtomic(d_CardChallenge, Constants.OFFSET_ZERO, d_tempBuffer, Constants.BLOCK_SIZE_24, Constants.BLOCK_SIZE_08);
		d_SignatureRefs[OFFSET_SIGN_MAC_AES].sign(d_tempBuffer, Constants.OFFSET_ZERO, Constants.BLOCK_SIZE_32, d_tempBuffer, Constants.OFFSET_ZERO);
	}
	
	/**
	 * This method calculate card challenge for establish secure channel.
	 * @param aid
	 * @param aidLen
	 * @author Mostak Ahmed
	 */
	private void calculateCardChallenge(byte[] aid, short aidLen){
		Util.arrayFillNonAtomic(d_tempBuffer, Constants.OFFSET_ZERO, (short)11, (byte)0x00);  //Label
		d_tempBuffer[11] = (byte)0x02;	//Derivation Constant : Card Challenge
		d_tempBuffer[12] = (byte)0x00;	//Separator
		d_tempBuffer[13] = (byte)0x00;	//MSB length
		d_tempBuffer[14] = (byte)0x40;	//LSB length
		d_tempBuffer[15] = (byte)0x01;	//Counter
		
		short offset = Constants.BLOCK_SIZE_16;
		Util.arrayCopyNonAtomic(d_sCounterSCP03, Constants.OFFSET_ZERO, d_tempBuffer, offset, (short)3);
		offset += 3;
		Util.arrayCopyNonAtomic(aid, Constants.OFFSET_ZERO, d_tempBuffer, offset, aidLen);
		offset += aidLen;
		d_SignatureRefs[OFFSET_SIGN_MAC_AES].sign(d_tempBuffer, Constants.OFFSET_ZERO, offset, d_tempBuffer, Constants.OFFSET_ZERO);
		Util.arrayCopyNonAtomic(d_tempBuffer, Constants.OFFSET_ZERO, d_CardChallenge, Constants.OFFSET_ZERO, Constants.BLOCK_SIZE_08);
	}
}

