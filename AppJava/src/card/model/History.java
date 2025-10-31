/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package card.model;

import java.sql.Timestamp;

/**
 *
 * @author admin
 */
public class History {
    private int ID;
    private String bienso;
    private Timestamp time; 
    private long money;

    public History(String bienso, Timestamp time, long money, int type, String userId) {
        this.bienso = bienso;
        this.time = time;
        this.money = money;
        this.type = type;
        this.userId = userId;
    }

    public History(int ID, String bienso, Timestamp time, int type, String userId) {
        this.ID = ID;
        this.bienso = bienso;
        this.time = time;
        this.type = type;
        this.userId = userId;
    }
    private  int type;
    private String userId;

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public History(int ID, String bienso, Timestamp time, long money, int type, String userId) {
        this.ID = ID;
        this.bienso = bienso;
        this.time = time;
        this.money = money;
        this.type = type;
        this.userId = userId;
    }

    public History(int ID, String bienso, Timestamp time, long money, int type) {
        this.ID = ID;
        this.bienso = bienso;
        this.time = time;
        this.money = money;
        this.type = type;
    }

    public History() {
    }

    public int getID() {
        return ID;
    }

    public void setID(int ID) {
        this.ID = ID;
    }

    public String getBienso() {
        return bienso;
    }

    public void setBienso(String bienso) {
        this.bienso = bienso;
    }

    public Timestamp getTime() {
        return time;
    }

    public void setTime(Timestamp time) {
        this.time = time;
    }

    public long getMoney() {
        return money;
    }

    public void setMoney(long price) {
        this.money = price;
    }

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }
    
    
}
