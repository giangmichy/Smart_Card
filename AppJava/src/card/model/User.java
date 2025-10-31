/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package card.model;

import card.connect.JDBCUtil;
import card.connect.UserDAO;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

/**
 *
 * @author admin
 */
public class User {
    
    private static final String PREFIX = "PC";
    private static final AtomicInteger counter = new AtomicInteger(1);
    private String id;
    private String fullName;
    private String dateOfBirth;
    private String phoneNumber;
    private String bienSo;
    private Long money;
    private byte[]avatar;
    private byte[] publicKey;

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public User(String id, String ten, String dob, String phone, String car_number, Long money) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    public int getStatus() {
        return status;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }
    public void setStatus(int status) {
        this.status = status;
    }
    public int getIsDelete() {
        return isDelete;
    }

    public User(String id, String fullName, String dateOfBirth, String phoneNumber, String bienSo, Long money, int status) {
        this.id = id;
        this.fullName = fullName;
        this.dateOfBirth = dateOfBirth;
        this.phoneNumber = phoneNumber;
        this.bienSo = bienSo;
        this.money = money;
        this.status = status;
    }
    public void setIsDelete(int isDelete) {
        this.isDelete = isDelete;
    }
    private int status;
    private int isDelete;
    

    public User(){};
    public User(String id, String fullName, String dateOfBirth, String phoneNumber, String bienSo) {
        this.id = id;
        this.fullName = fullName;
        this.dateOfBirth = dateOfBirth;
        this.phoneNumber = phoneNumber;
        this.bienSo = bienSo;
    }

    @Override
    public String toString() {
        return "User{" +
                "id='" + id + '\'' +
                ", fullName='" + fullName + '\'' +
                ", dateOfBirth=" + dateOfBirth +
                ", sex='" + phoneNumber + '\'' +
                ", address='" + bienSo + '\'' +
                ", money=" + money +
                ", avatar=" + Arrays.toString(avatar) +
                '}';
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getDateOfBirth() {
        return dateOfBirth;
    }

    public void setDateOfBirth(String dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public String getBienSo() {
        return bienSo;
    }

    public void setBienSo(String bienSo) {
        this.bienSo = bienSo;
    }

    public long getMoney() {
        return money;
    }

    public void setMoney(Long money) {
        this.money = money;
    }

    public byte[] getAvatar() {
        return avatar;
    }  

    public void setAvatar(byte[] avatar) {
        this.avatar = avatar;
    } 
    
    public String generateId() {
    StringBuilder id = new StringBuilder("PC");
    String idBefore = UserDAO.getUserWithMaxId(); // Lấy ID lớn nhất hiện tại
    if (idBefore == null) {
        return "PC0001";
    } else {
   
        String subId = idBefore.substring(2); 
        int numericPart = Integer.parseInt(subId);
        numericPart++; // Tăng giá trị lên 1
        String formattedNumber = String.format("%04d", numericPart);

        return id.append(formattedNumber).toString();
    }
}

}
