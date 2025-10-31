/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package card.common;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 *
 * @author ADMIN
 */
public class ByteUtil{
    
     public static byte[] convertFileToBytes(File file) throws IOException {
         FileInputStream fileInputStream = new FileInputStream(file);
        byte[] bytes = new byte[(int) file.length()];
        fileInputStream.read(bytes);
        fileInputStream.close();
        return bytes;
    }
    
}
