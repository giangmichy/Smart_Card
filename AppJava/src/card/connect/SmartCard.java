/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package card.connect;

import card.common.Constants;
import static card.common.Constants.AID;
import static card.common.Constants.CLA;
import static card.common.Constants.INS_ATTEMPTS_LEFT;
import static card.common.Constants.INS_AUTHENTICATE;
import static card.common.Constants.INS_CHANGE_IMAGE;
import static card.common.Constants.INS_CHANGE_MONEY;
import static card.common.Constants.INS_CHANGE_PIN;
import static card.common.Constants.INS_CREATE_INFO;
import static card.common.Constants.INS_CREATE_PIN;
import static card.common.Constants.INS_DISPLAY_INFO;
import static card.common.Constants.INS_DISPLAY_MONEY;
import static card.common.Constants.INS_PUBLIC_KEY;
import static card.common.Constants.INS_VERIFY;
import static card.common.Constants.P1;
import static card.common.Constants.P2;
import card.model.User;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.smartcardio.*;
import javax.swing.JOptionPane;

/**
 *
 * @author admin
 */
public class SmartCard {

    private Card card;
    private CardChannel channel;
    
    public boolean connectCard() throws Exception {
        TerminalFactory factory = TerminalFactory.getDefault();
        CardTerminals terminals = factory.terminals();
        CardTerminal terminal = terminals.list().get(0);

        card = terminal.connect("*");
        System.out.println("Card protocol: " + card.getProtocol());
        channel = card.getBasicChannel();

        CommandAPDU selectApplet = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AID);
        ResponseAPDU response = channel.transmit(selectApplet);
        return response.getSW() == 0x9000;
    }

    public void disconnectCard() {
        try {
            if (card != null) {
                card.disconnect(false);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean sendAllData(User user) {
        try {
            byte[] idBytes = user.getId().getBytes();
            byte[] nameBytes = user.getFullName().getBytes();
            byte[] phoneBytes = user.getPhoneNumber().getBytes();
            byte[] dobBytes = user.getDateOfBirth().getBytes();
            byte[] carNumberBytes = user.getBienSo().getBytes();

            // Tạo mảng byte chứa toàn bộ dữ liệu
            byte[] allData = new byte[16 + 64 + 16 + 16 + 16];
            System.arraycopy(idBytes, 0, allData, 0, idBytes.length);
            System.arraycopy(nameBytes, 0, allData, 16, nameBytes.length);
            System.arraycopy(dobBytes, 0, allData, 16 + 64, dobBytes.length);
            System.arraycopy(phoneBytes, 0, allData, 16 + 64 + 16, phoneBytes.length);
            System.arraycopy(carNumberBytes, 0, allData, 16 + 64 + 16 + 16, carNumberBytes.length);

            CommandAPDU command = new CommandAPDU(CLA, INS_CREATE_INFO, P1, P2, allData);
            ResponseAPDU response = channel.transmit(command);

            if (response.getSW() != 0x9000) {
                return false;
            }
            return true;
        } catch (CardException ex) {
            Logger.getLogger(SmartCard.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }
    }

    public User readAllData() {
        try {
            CommandAPDU command = new CommandAPDU(CLA, INS_DISPLAY_INFO, P1, P2);
            ResponseAPDU response = channel.transmit(command);

            if (response.getSW() != 0x9000) {
                try {
                    throw new Exception("Lỗi khi đọc dữ liệu, mã phản hồi: " + Integer.toHexString(response.getSW()));
                } catch (Exception ex) {
                    Logger.getLogger(SmartCard.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            byte[] data = response.getData();

            String id = new String(data, 0, 16).trim();
            String name = new String(data, 16, 64).trim();
            String dob = new String(data, 16 + 64, 16).trim();
            String phone = new String(data, 16 + 64 + 16, 16).trim();
            String carNumber = new String(data, 16 + 64 + 16 + 16, 16).trim();

            User user = new User(id, name, dob, phone, carNumber);
            return user;
        } catch (CardException ex) {
            Logger.getLogger(SmartCard.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    public int createPin(String pin) {
        byte[] pinBytes = pin.getBytes();
        CommandAPDU command = new CommandAPDU(CLA, INS_CREATE_PIN, P1, P2, pinBytes);
        try {
            ResponseAPDU response = channel.transmit(command);
            return response.getSW();
        } catch (CardException ex) {
            Logger.getLogger(SmartCard.class.getName()).log(Level.SEVERE, null, ex);
            return -1;
        }
    }

    public int changePin(String pin) {
        byte[] pinBytes = pin.getBytes();
        CommandAPDU command = new CommandAPDU(CLA, INS_CHANGE_PIN, P1, P2, pinBytes);

        try {
            ResponseAPDU response = channel.transmit(command);
            return response.getSW();
        } catch (CardException ex) {
            Logger.getLogger(SmartCard.class.getName()).log(Level.SEVERE, null, ex);
            return -1;
        }
    }

    public int verifyPin(String pin) {
        byte[] pinBytes = pin.getBytes();
        CommandAPDU command = new CommandAPDU(CLA, INS_VERIFY, P1, P2, pinBytes);

        try {
            ResponseAPDU response = channel.transmit(command);
            return response.getSW();
        } catch (CardException ex) {
            Logger.getLogger(SmartCard.class.getName()).log(Level.SEVERE, null, ex);
            return -1;
        }
    }

    public int topUpcard(String money) {
        byte[] moneyBytes = money.getBytes();
        byte[] data = new byte[16];
        System.arraycopy(moneyBytes, 0, data, 0, moneyBytes.length);
        CommandAPDU command = new CommandAPDU(CLA, INS_CHANGE_MONEY, P1, P2, data);
        try {
            ResponseAPDU response = channel.transmit(command);
            return response.getSW();
        } catch (CardException ex) {
            Logger.getLogger(SmartCard.class.getName()).log(Level.SEVERE, null, ex);
            return -1;
        }
    }

    public String readMoney() {
        CommandAPDU command = new CommandAPDU(CLA, INS_DISPLAY_MONEY, P1, P2);
        try {
            ResponseAPDU response = channel.transmit(command);
            byte[] data = response.getData();
            String money = new String(data, 0, 16).trim();
            System.out.println(money);
            return money;
        } catch (CardException ex) {
            Logger.getLogger(SmartCard.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    public String attemptsLeft() {
        CommandAPDU command = new CommandAPDU(CLA, INS_ATTEMPTS_LEFT, P1, P2);
        try {

            ResponseAPDU response = channel.transmit(command);
            byte[] data = response.getData();
            byte attempts = data[0];  // Lấy giá trị số ở vị trí đầu tiên của mảng byte
            return String.valueOf(attempts);  // Trả về giá trị dưới dạng chuỗi

        } catch (CardException ex) {
            Logger.getLogger(SmartCard.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    public int saveImage(byte[] images) {
        CommandAPDU command = new CommandAPDU(CLA, INS_CHANGE_IMAGE, P1, P2, images);
        try {
            ResponseAPDU response = channel.transmit(command);
            return response.getSW();
        } catch (CardException ex) {
            Logger.getLogger(SmartCard.class.getName()).log(Level.SEVERE, null, ex);
            return -1;
        }
    }

    public byte[] readImage() {
        // Tạo APDU command
        CommandAPDU command = new CommandAPDU(CLA, Constants.INS_DISPLAY_IMAGE, P1, P2);
        try {
            ResponseAPDU response = channel.transmit(command);
            byte[] data = response.getData();
            System.out.println("check" + data);
            if (data != null && data.length > 0) {
                return data; // Trả về mảng byte nếu dữ liệu hợp lệ
            } else {
                System.out.println("No data received.");
                return null;
            }
//            return data != null && data.length > 0 ? data : null;
        } catch (CardException ex) {
            Logger.getLogger(SmartCard.class.getName()).log(Level.SEVERE, "CardException occurred", ex);
            return null;
        }
    }

    // RSA
    public byte[] receivePublicKey() {
        try {
            CommandAPDU getPublicKeyCmd = new CommandAPDU(CLA, INS_PUBLIC_KEY, P1, P2);
            ResponseAPDU response = channel.transmit(getPublicKeyCmd);
            byte[] publicKeyData = response.getData();
            return publicKeyData;
        } catch (Exception e) {
            return null;
        }
    }
    
    public boolean authenticate(byte[] publicKeyData) {
        try {
            String message = generateRandomString();
            byte[] rawMessage = message.getBytes();

            // Tạo APDU chứa thông điệp ngẫu nhiên
            CommandAPDU commandAPDU = new CommandAPDU(CLA, INS_AUTHENTICATE, P1, P2, rawMessage);
            ResponseAPDU responseAPDU = channel.transmit(commandAPDU);
            int sw = responseAPDU.getSW();
            if (sw == 0x9000) {
                byte[] encryptedData = responseAPDU.getData();
                RSAPublicKey publicKey = restorePublicKey(publicKeyData); // Giả sử bạn đã lưu khóa công khai
                byte[] decryptedMessage = rsaDecrypt(responseAPDU.getData(), publicKey);
                if (Arrays.equals(rawMessage, decryptedMessage)) {
                   return true;
                }}
                return false;
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, "Error during authentication: " + e.getMessage());
            return false;
        }
    }
    
    private byte[] rsaDecrypt(byte[] data, RSAPublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    private RSAPublicKey restorePublicKey(byte[] publicKeyData) {
        try {
            BigInteger modulus = new BigInteger(1, publicKeyData, 0, 128);
            BigInteger exponent = new BigInteger(1, publicKeyData, 128, 3);
            RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(spec);
        } catch (Exception ex) {
            Logger.getLogger(SmartCard.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    public static String generateRandomString() {
        // Các ký tự hợp lệ (chữ cái và số)
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        SecureRandom random = new SecureRandom();  // Sử dụng SecureRandom để tăng tính bảo mật
        StringBuilder sb = new StringBuilder(16);  // Chuỗi kết quả có độ dài 16 ký tự

        for (int i = 0; i < 16; i++) {
            int randomIndex = random.nextInt(characters.length());
            sb.append(characters.charAt(randomIndex));  // Thêm ký tự ngẫu nhiên vào chuỗi
        }
        return sb.toString();
    }
    
    public int unLock ()
    {
        try {
        CommandAPDU command = new CommandAPDU(0xA0, 0x06, P1, P2);
            ResponseAPDU response = channel.transmit(command);
            return response.getSW();
        } catch (CardException ex) {
            Logger.getLogger(SmartCard.class.getName()).log(Level.SEVERE, null, ex);
            return -1;
        }
    }

}
