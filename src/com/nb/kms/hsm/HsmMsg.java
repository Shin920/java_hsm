package com.nb.kms.hsm;

import java.io.Serializable;
import com.nb.kms.hsm.EventMsg.*;

public class HsmMsg implements Serializable {

    private static final long serialVersionUID = 1L;
    private int operation;
    private hsmMsgHeader header;
    private int keyType;
    private String keyGenType;
    private int etcsId;
    private int serialNum;
    private int newSerialNum;
    private int newEtcsId;
    private String expirationDate; // 유효기간 필드 추가
    private byte[] data; /* CBC-MAC 계산할 원본 데이터 */


    //HSM Staus 조회용 메세지형식
    public HsmMsg(hsmMsgHeader header, int operation) {
        this.header = header;
        this.operation = operation;
    }

    // 기본 메세지 형식
    public HsmMsg(hsmMsgHeader header, int operation, int keyType, int etcsId, int serialNum, String keyGenType) {
        this.header = header;
        this.operation = operation;
        this.keyType = keyType;
        this.etcsId = etcsId;
        this.serialNum = serialNum;
        this.keyGenType = keyGenType;
    }

    // CBC 계산, 암복호화, 키 주입의 경우 data = Key
    public HsmMsg(hsmMsgHeader header, int operation, int keyType, int etcsId, int serialNum, String keyGenType, byte[] data) {
        this.header = header;
        this.operation = operation;
        this.keyType = keyType;
        this.etcsId = etcsId;
        this.serialNum = serialNum;
        this.keyGenType = keyGenType;
        this.data = data;
    }

    // 키 복사용 메세지 형식
    public HsmMsg(hsmMsgHeader header, int operation, int keyType, int etcsId, int serialNum, String keyGenType, int newEtcsId, int newSerialNum) {
        this.header = header;
        this.operation = operation;
        this.keyType = keyType;
        this.etcsId = etcsId;
        this.serialNum = serialNum;
        this.keyGenType = keyGenType;
        this.newSerialNum = newSerialNum;
        this.newEtcsId = newEtcsId;
    }

    // UPDATE_KEY
    // 유효기간 업데이트용 메세지 형식
    public HsmMsg(hsmMsgHeader header, int operation, int keyType, String keyGenType, String expirationDate) {
        this.header = header;
        this.operation = operation;
        this.keyType = keyType;
        this.keyGenType = keyGenType;
        this.expirationDate = expirationDate;
    }

    public int getEtcsId() {
        return etcsId;
    }

    public void setEtcsId(int etcsId) {
        this.etcsId = etcsId;
    }

    public int getSerialNum() {
        return serialNum;
    }

    public void setSerialNum(int serialNum) {
        this.serialNum = serialNum;
    }

    // getters and setters
    public hsmMsgHeader getHeader() {
        return header;
    }

    public int getNewSerialNum() {
        return newSerialNum;
    }

    public void setNewSerialNum(int newSerialNum) {
        this.newSerialNum = newSerialNum;
    }

    public int getNewEtcsId() {
        return newEtcsId;
    }

    public void setNewEtcsId(int newEtcsId) {
        this.newEtcsId = newEtcsId;
    }

    public void setHeader(hsmMsgHeader header) {
        this.header = header;
    }

    public int getOperation() {
        return operation;
    }

    public void setOperation(int operation) {
        this.operation = operation;
    }

    public int getKeyType() {
        return keyType;
    }

    public void setKeyType(int keyType) {
        this.keyType = keyType;
    }

    public String getKeyGenType() {
        return keyGenType;
    }

    public void setKeyGenType(String keyGenType) {
        this.keyGenType = keyGenType;
    }

    public String getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(String expirationDate) {
        this.expirationDate = expirationDate;
    }

    public long getSlotId() {
        return HSM_INFO.SLOT_ID;
    }

    public String getPassword() {
        return HSM_INFO.PASSWORD;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] keyData) {
        this.data = keyData;
    }

    // 메시지 구조의 공통 인터페이스

    // hsmMsgHeader 클래스
    public static class hsmMsgHeader implements Serializable {

        private static final long serialVersionUID = 2L;
        //id = byte
        private byte senderId;
        private String address;
        private int port;

        public hsmMsgHeader(byte senderId, String address, int port) {
            this.senderId = senderId;
            this.address = address;
            this.port = port;
        }

        public byte getSenderId() {
            return senderId;
        }

        public void setSenderId(byte senderId) {
            this.senderId = senderId;
        }

        public String getAddress() {
            return address;
        }

        public void setAddress(String address) {
            this.address = address;
        }

        public int getPort() {
            return port;
        }

        public void setPort(int port) {
            this.port = port;
        }
    }


}