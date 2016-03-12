/*
 * Date Created: Mar 31, 2014
 * Release Date: Oct 12, 2014
 * Version: 1.1.0
 */
package com.konasl.demoapplet;

/**
 * CSP <br> This class is for all kind of key container and their basic information 
 *  @author Rakeb
 */
public class CSP {
	protected byte		c_accessCondition;
	protected byte		c_keyType;
	protected short		c_maxLen;
	protected short		c_storedLen;
	protected byte[]	c_body;
	
	protected CSP(short maxLen, byte ac) {
		this.c_accessCondition 	= ac;
		this.c_keyType			= (byte)0x00;
		this.c_maxLen			= maxLen;
		this.c_body				= new byte[maxLen];
	}
}
