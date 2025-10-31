/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package card.connect;

import card.model.History;
import card.model.User;
import java.sql.Timestamp;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;

/**
 *
 * @author admin
 */
public class CarDAO {

    public static void insertHistory(History his) {
        String sql = "INSERT INTO history_input_output (time, type, money, car_number, user_id) VALUES (?, ?, ?, ?, ?)";

        try {
            Connection connection = JDBCUtil.getConnection();
            PreparedStatement sttm = connection.prepareStatement(sql);
            sttm.setTimestamp(1, his.getTime());
            sttm.setInt(2, his.getType());
            sttm.setLong(3, his.getMoney());
            sttm.setString(4, his.getBienso());
            sttm.setString(5, his.getUserId());
            System.out.println("them thanh cong");
            sttm.execute();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
        public static ArrayList<History> searchHistoryByUserId( String txt, int type) {
        ArrayList<History> list = new ArrayList<>();
        String sql = "Select * from history_input_output where user_id = ? and type = ?";
        try {
            Connection connection = JDBCUtil.getConnection();
            PreparedStatement sttm = connection.prepareStatement(sql);
            sttm.setString(1, txt);
            sttm.setInt(2, type);
            
            ResultSet rs = sttm.executeQuery();
            while(rs.next()){
                int id = rs.getInt("id");
                Timestamp  time = rs.getTimestamp("time");
                String bienSo = rs.getString("car_number");
                int type1 = rs.getInt("type");
                long money = rs.getLong("money");
                String userId = rs.getString("user_id");
                History his = new History(bienSo, time, money, type1, userId);
                list.add(his);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return list;
    }
        public static ArrayList<History> searchHistoryByCarNumber(String txt, int type) {
        ArrayList<History> list = new ArrayList<>();
        String sql = "Select * from history_input_output where car_number = ? and type = ?";
        try {
            Connection connection = JDBCUtil.getConnection();
            PreparedStatement sttm = connection.prepareStatement(sql);
            sttm.setString(1, txt);
            sttm.setInt(2, type);
            ResultSet rs = sttm.executeQuery();
            while(rs.next()){
                int id = rs.getInt("id");
                Timestamp  time = rs.getTimestamp("time");
                String bienSo = rs.getString("car_number");
                int type1 = rs.getInt("type");
                long money = rs.getLong("money");
                String userId = rs.getString("user_id");
                History his = new History(bienSo, time, money, type1, userId);
                list.add(his);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return list;
    }

    public static void updateType(String id, int type) {

        String sql = "UPDATE history_input_output SET type = ? WHERE id = ?";

        try {
            Connection connection = JDBCUtil.getConnection();
            PreparedStatement sttm = connection.prepareStatement(sql);
            sttm.setDouble(1, type);
            sttm.setString(2, id);

            sttm.execute();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static ArrayList<History> getAllByType(int type) {
        ArrayList<History> list = new ArrayList<>();
        String sql = "Select * from history_input_output where type = ?";
        try {
            Connection connection = JDBCUtil.getConnection();
            PreparedStatement sttm = connection.prepareStatement(sql);
            sttm.setInt(1, type);
            
            ResultSet rs = sttm.executeQuery();
            while(rs.next()){
                int id = rs.getInt("id");
                Timestamp  time = rs.getTimestamp("time");
                String bienSo = rs.getString("car_number");
                int type1 = rs.getInt("type");
                long money = rs.getLong("money");
                String userId = rs.getString("user_id");
                History his = new History(bienSo, time, money, type1, userId);
                list.add(his);
            }
        } catch (Exception e) {
            e.printStackTrace();

        }
        return list;
    }

}
