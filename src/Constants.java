/*
 * Date Created: Mar 31, 2014
 * Release Date: December 05, 2014
 * Version: 1.2.1
 */
package com.konasl.demoapplet;

import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Constants <br>
 * All constants values used in DemoApplet are here. 
 *  @author Rakeb
 */
public class Constants {
	public static final byte TRUE									= (byte)0x01;
	public static final byte FALSE									= (byte)0x00;
	
	public static final short OFFSET_ZERO							= (short)0x0000;
	public static final short BLOCK_SIZE_08							= (short)8;
	public static final short BLOCK_SIZE_16							= (short)16;
	public static final short BLOCK_SIZE_24							= (short)24;
	public static final short BLOCK_SIZE_32							= (short)32;
	public static final short BLOCK_SIZE_48							= (short)48;
	public static final short BLOCK_SIZE_240						= (short)240;
	
	public static final byte CONSTANT_RB_128 						= (byte)0x87;
	public static final short KEY_LEN_3DES_2KEY						= (short)0x0010;
    
    //Proprietary
	public final static short SW_SIGNATURE_VERIFICATION_FAILED	 	= (short)0x6901;
	public final static short SW_MUDULUS_NOT_INITIALIZED			= (short)0x6902;
	public final static short SW_SE_NOT_RESTORED					= (short)0x6903;
	public final static short SW_ALG_NOT_SUPPORTED					= (short)0x6904;
	public final static short SW_KEYPAIR_NOT_SUPPORTED				= (short)0x6905;
	public final static short SW_KEY_INITIALIZATION_FAILED			= (short)0x6906;
	public final static short SW_KEY_NOT_INITIALIZE					= (short)0x6912;
	public final static short SW_INVALID_DATA_BLOCK					= (short)0x6910;
	public final static short SW_INVALID_INS_CLA					= (short)0x69F0;
	public final static short SW_APPLET_DEAD						= (short)0x69F1;
//	public final static short SW_PIN_FAILED_00	 					= (short)0x63C0;

//	public final static short SW_DEBUG			 					= (short)0x9999;
	public final static short SW_OPERATION_STATE					= (short)0x9900;
	
    //PIN
	public final static short PIN_MAX_COUNT							= (short)0x0002;
	
	public final static short PIN_OFFSET_SO							= (short)0x0000;
	public final static short PIN_OFFSET_USER						= (short)0x0001;
	
	public final static byte PIN_MAX_SIZE							= (byte)0x08;
	public final static byte PIN_TRY_LIMIT							= (byte)0x03;
	
	//Operation State
	public final static byte STATE_IDLE								= (byte)0x00;
	public final static byte STATE_AUTHENTICATE						= (byte)0x01;
	public final static byte STATE_AUTHENTICATE_IDLE				= (byte)0x02;
	public final static byte STATE_PUT_DATA							= (byte)0x03;
	public final static byte STATE_SIGN_VERIFY						= (byte)0x04;
//	public final static byte DESTROY								= (byte)0x03;
	
	//Keys
	public final static short CSP_DEM_AUTH_KEY_MAX_LEN				= (short)16;
	public final static short CSP_DEM_MAC_KEY_MAX_LEN				= (short)64;
	public final static short CSP_DEM_WRAP_KEY_MAX_LEN				= (short)32;
	public final static short CSP_DEM_CON_SECRET_MAX_LEN			= (short)32;
	public final static short CSP_DEM_3P_PUB_MAX_LEN				= (short)272; // 2048 + 16*8
	
	// Key length in byte
	public final static short LENGTH_DES3_2KEY						= (short)16;
	public final static short LENGTH_DES3_3KEY						= (short)24;
	public final static short LENGTH_AES_128						= (short)16;
	public final static short LENGTH_AES_192						= (short)24;
	public final static short LENGTH_AES_256						= (short)32;
	public final static short LENGTH_RSA_1024						= (short)128;
	public final static short LENGTH_RSA_2048						= (short)256;
	
	//EC key length
	public final static short LENGTH_EC_192							= (short)49;
	public final static short LENGTH_EC_224							= (short)57;
	public final static short LENGTH_EC_256							= (short)65;
	public final static short LENGTH_EC_384							= (short)97;
	public final static short LENGTH_EC_521							= (short)133;
	
	public final static short LENGTH_SEED_TDES						= (short)21;
	public final static short LENGTH_SEED_AES_128					= (short)32;
	public final static short LENGTH_SEED_AES_192					= (short)40;
	public final static short LENGTH_SEED_AES_256					= (short)48;
	
	//Algorithm Reference Constants
	public static final byte ALG_MIN						= (byte)0x01;
	public static final byte DS_ALG_MAX 					= (byte)0x21;
	public static final byte HASH_ALG_MAX 					= (byte)0x05;
	public static final byte CON_ALG_MAX 					= (byte)0x12;
	
	public static final byte DS_ALG_AES_MIN  				= (byte)0x01;
	public static final byte DS_ALG_AES_MAX					= (byte)0x02;
	
	public static final byte DS_ALG_DES_MIN  				= (byte)0x03;
	public static final byte DS_ALG_DES_MAX					= (byte)0x0C;
	
	public static final byte DS_ALG_HMAC_MIN 				= (byte)0x0D;
	public static final byte DS_ALG_HMAC_MAX				= (byte)0x10;
	
	public static final byte DS_ALG_RSA_MIN	  				= (byte)0x11;
	public static final byte DS_ALG_RSA_MAX					= (byte)0x1C;
	
	public static final byte DS_ALG_ECDSA_MIN 				= (byte)0x1D;
	public static final byte DS_ALG_ECDSA_MAX	 			= (byte)0x21;
	
	public static final byte HASH_ALG_SHA1_MIN 				= (byte)0x01;
	public static final byte HASH_ALG_SHA1_MAX	 			= (byte)0x01;
	
	public static final byte HASH_ALG_SHA2_MIN 				= (byte)0x02;
	public static final byte HASH_ALG_SHA2_MAX	 			= (byte)0x05;
	
	public static final byte CON_ALG_AES_MIN  				= (byte)0x01;
	public static final byte CON_ALG_AES_MAX				= (byte)0x08;
	
	public static final byte CON_ALG_DES_MIN  				= (byte)0x09;
	public static final byte CON_ALG_DES_MAX				= (byte)0x10;
	
	public static final byte CON_ALG_RSA_MIN  				= (byte)0x11;
	public static final byte CON_ALG_RSA_MAX				= (byte)0x12;
	
	public static final byte CON_ALG_AES_CBC_MIN			= (byte)0x01;
	public static final byte CON_ALG_AES_CBC_MAX			= (byte)0x04;
	
	public static final byte CON_ALG_AES_ECB_MIN			= (byte)0x05;
	public static final byte CON_ALG_AES_ECB_MAX			= (byte)0x08;
	
	public static final byte CON_ALG_DES_CBC_MIN			= (byte)0x09;
	public static final byte CON_ALG_DES_CBC_MAX			= (byte)0x0C;
	
	public static final byte CON_ALG_DES_ECB_MIN			= (byte)0x0D;
	public static final byte CON_ALG_DES_ECB_MAX			= (byte)0x10;
	
	public static final byte ALG_REF_WRAP_AES				= (byte)0x04;	//Algorithm ALG_AES_CBC_NOPAD 01h use for testing.
																	//Final Algorithm ALG_AES_CBC_PKCS5 reference number 04h
	
	public static final byte[] BASE_AUTH_KEY = { 
		(byte)0x60, (byte)0x61, (byte)0x62, (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66, (byte)0x67,
        (byte)0x68, (byte)0x69, (byte)0x6a, (byte)0x6b, (byte)0x6c, (byte)0x6d, (byte)0x6e, (byte)0x6f
	};
	
//	public static final byte[] BASE_WRAP_KEY = {
//		(byte)0x11,	(byte)0x22,	(byte)0x33,	(byte)0x44,	(byte)0x55,	(byte)0x66,	(byte)0x77,	(byte)0x88,
//		(byte)0x11, (byte)0x22,	(byte)0x33,	(byte)0x44,	(byte)0x55,	(byte)0x66,	(byte)0x77,	(byte)0x88
//	};
	public static final byte[] BASE_WRAP_KEY = {
		(byte)0x40, (byte)0x41, (byte)0x42, (byte)0x43, (byte)0x44, (byte)0x45, (byte)0x46, (byte)0x47,
        (byte)0x48, (byte)0x49, (byte)0x4A, (byte)0x4B, (byte)0x4C, (byte)0x4D, (byte)0x4E, (byte)0x4F,
        (byte)0x50, (byte)0x51, (byte)0x52, (byte)0x53, (byte)0x54, (byte)0x55, (byte)0x56, (byte)0x57,
        (byte)0x58, (byte)0x59, (byte)0x5A, (byte)0x5B, (byte)0x5C, (byte)0x5D, (byte)0x5E, (byte)0x5F
	};
	
	public static final byte[] ZEROES = {
    	(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
    	(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
    };
	
	public static final byte[] AID = {
		(byte)0x6B, (byte)0x6F, (byte)0x6E, (byte)0x61, (byte)0x73, (byte)0x6C, (byte)0x66, (byte)0x69,
		(byte)0x70, (byte)0x73, (byte)0x30
	};

//	public static final byte[] HMAC_00_KEY = { 
//        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
//        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
//        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
//	};
	
	 public static final byte[] DS_ALGO = {
	    	Signature.ALG_AES_CMAC_128,
		 	Signature.ALG_AES_MAC_128_NOPAD,
	    	Signature.ALG_DES_MAC4_ISO9797_1_M2_ALG3,
	    	Signature.ALG_DES_MAC4_ISO9797_M1,
	    	Signature.ALG_DES_MAC4_ISO9797_M2,
	    	Signature.ALG_DES_MAC4_NOPAD,
	    	Signature.ALG_DES_MAC4_PKCS5,
	    	Signature.ALG_DES_MAC8_ISO9797_1_M2_ALG3,
	    	Signature.ALG_DES_MAC8_ISO9797_M1,
	    	Signature.ALG_DES_MAC8_ISO9797_M2,
	    	Signature.ALG_DES_MAC8_NOPAD,
	    	Signature.ALG_DES_MAC8_PKCS5,
			Signature.ALG_HMAC_SHA1,			
			Signature.ALG_HMAC_SHA_256,
			Signature.ALG_HMAC_SHA_384,
			Signature.ALG_HMAC_SHA_512,
			Signature.ALG_RSA_SHA_ISO9796,
			Signature.ALG_RSA_SHA_PKCS1,
			Signature.ALG_RSA_SHA_PKCS1_PSS,
			Signature.ALG_RSA_SHA_RFC2409,
			Signature.ALG_RSA_SHA_224_PKCS1,
			Signature.ALG_RSA_SHA_224_PKCS1_PSS,
			Signature.ALG_RSA_SHA_256_PKCS1,
			Signature.ALG_RSA_SHA_256_PKCS1_PSS,
			Signature.ALG_RSA_SHA_384_PKCS1,
			Signature.ALG_RSA_SHA_384_PKCS1_PSS,
			Signature.ALG_RSA_SHA_512_PKCS1,
			Signature.ALG_RSA_SHA_512_PKCS1_PSS,
			Signature.ALG_ECDSA_SHA,
			Signature.ALG_ECDSA_SHA_224,
			Signature.ALG_ECDSA_SHA_256,
			Signature.ALG_ECDSA_SHA_384,
			Signature.ALG_ECDSA_SHA_512
	    };
	    
	    public static final byte[] HASH_ALGO ={
		    MessageDigest.ALG_SHA,
		    MessageDigest.ALG_SHA_224,
			MessageDigest.ALG_SHA_256,
			MessageDigest.ALG_SHA_384,
			MessageDigest.ALG_SHA_512
	    };
	    
	    public static final byte[] CON_ALGO = {
	    	Cipher.ALG_AES_BLOCK_128_CBC_NOPAD,
	    	Cipher.ALG_AES_CBC_ISO9797_M1,
			Cipher.ALG_AES_CBC_ISO9797_M2,
			Cipher.ALG_AES_CBC_PKCS5,
			
			Cipher.ALG_AES_BLOCK_128_ECB_NOPAD,			
			Cipher.ALG_AES_ECB_ISO9797_M1,
			Cipher.ALG_AES_ECB_ISO9797_M2,
			Cipher.ALG_AES_ECB_PKCS5,
			
			Cipher.ALG_DES_CBC_ISO9797_M1,
	    	Cipher.ALG_DES_CBC_ISO9797_M2,
	    	Cipher.ALG_DES_CBC_NOPAD,
			Cipher.ALG_DES_CBC_PKCS5,
			
			Cipher.ALG_DES_ECB_ISO9797_M1,
			Cipher.ALG_DES_ECB_ISO9797_M2,
			Cipher.ALG_DES_ECB_NOPAD,
			Cipher.ALG_DES_ECB_PKCS5,
			
			Cipher.ALG_RSA_NOPAD,
			Cipher.ALG_RSA_PKCS1
	    };
	    
	    public static final byte[] APPLET_INFO = {
	    	(byte)0x10, (byte)0x03, (byte)0x01, (byte)0x02, (byte)0x02, //tag 10, len 03, data(v1.2.2): major, minor, revision (1.2.2 for random without set seed) 
	    	(byte)0x20, (byte)0x04, (byte)0x09, (byte)0x0C, (byte)0x07, (byte)0xDE //tag 20, len 04, data(09.12.2014): day, month, year
	    };
}
