package com.nb.kms.hsm;

import java.sql.*;

import config.AppConfig.*;

public class HsmDBService {
    private static HsmDBService instance;

    private HsmDBService() {
        try {
            Class.forName(DB_CONFIG.DRIVER_NAME);
        } catch (ClassNotFoundException e) {
            Logger.error("Database driver not found", e);
        }
    }

    public static synchronized HsmDBService getInstance() {
        if (instance == null) {
            instance = new HsmDBService();
        }
        return instance;
    }

    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection(
                DB_CONFIG.CONNECTION_INFORMATION,
                DB_CONFIG.KMC_ID,
                DB_CONFIG.KMC_PASSWORD);
    }

    public String getKCV(String keyLabel) {
        String sql = "SELECT kcv FROM TB_KMC_KEY WHERE key_label = ?";
        String kcv = null;

        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, keyLabel);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    kcv = rs.getString("kcv");
                    Logger.log("INFO", "KCV retrieved for key label: " + keyLabel);
                } else {
                    Logger.log("INFO", "No key found with label: " + keyLabel);
                }
            }
        } catch (SQLException e) {
            Logger.error("Error retrieving KCV from database", e);
        }

        return kcv;
    }

    public void updateKeyExpiry(String keyName, String newExpiryDate) {
        String sql = "UPDATE TB_KMC_KEY SET valid_period_end = ? WHERE key_label = ?";
        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, newExpiryDate);
            pstmt.setString(2, keyName);
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows > 0) {
                Logger.log("INFO", "Key expiry date updated: " + keyName);
            } else {
                Logger.log("INFO", "No key found with name: " + keyName);
            }
        } catch (SQLException e) {
            Logger.error("Error updating key expiry date in database", e);
        }
    }
}