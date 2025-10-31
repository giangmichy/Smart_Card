package card.connect;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JDBCUtil {

    public static Connection getConnection() throws ClassNotFoundException {
        Connection conn = null;
        String url = "jdbc:mysql://localhost:3306/parking_card";
        String username = "root";
        String password = "1234567890";
//        Connection conn = null;
//        String url = "jdbc:mysql://localhost:3306/parking_card";
//                        String username = "student";
//                        String password = "student";
        try {
            conn = DriverManager.getConnection(url, username, password);

        } catch (SQLException e) {

            e.printStackTrace();
        }

        return conn;
    }

    public static void closeConnection(Connection conn) {
        try {
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws ClassNotFoundException {

        JDBCUtil.closeConnection(getConnection());;

//		if(con!=null)
//		{
//			System.out.println("oke");
//		}
    }
}
