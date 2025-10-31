/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package card.common;

/**
 *
 * @author admin
 */
public class Constants {
    
    public static final byte[] AID = new byte[]{0x11, 0x22, 0x33, 0x44, 0x55, 0x00};
    public static final byte CLA =  (byte)0XB0;
    public static final byte P1 =  0X00;
    public static final byte P2 =  0X00;
    
    public static final byte INS_VERIFY = 0x5;
    public static final byte INS_CREATE_PIN = 0x03;    
    public static final byte INS_CHANGE_PIN = 0x04;
    
    

    public static final byte INS_CREATE_INFO = 0x01;    
    public static final byte INS_DISPLAY_INFO = 0x02;
    public static final byte INS_CHANGE_INFO = 0x01;


    public static final byte INS_CHANGE_IMAGE = 0x21;
    public static final byte INS_DISPLAY_IMAGE = 0x22;
    
    public static final byte INS_CHANGE_MONEY = 0x10;
    public static final byte INS_DISPLAY_MONEY = 0x11;
    public static final byte INS_ATTEMPTS_LEFT = 0x20;
    public static final String CARD_BLOCK = "Thẻ đã bị khóa!";
    public static final byte INS_PUBLIC_KEY = 0x30;
    public static final byte INS_AUTHENTICATE = 0x31;
    
    public static int ENTRY_CAR = 0;
    public static int EXIT_CAR = 1;
}
