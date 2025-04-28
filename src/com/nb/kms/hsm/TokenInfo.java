package com.nb.kms.hsm;

import java.io.Serial;
import java.io.Serializable;

// HSM 상태정보 확인용 TokenInfo 토큰(보안모듈)정보 클래스
public class TokenInfo implements Serializable{
    @Serial
    private static final long serialVersionUID = 1L;
    private String label;
    private String manufacturerID;
    private String model;
    private String serialNumber;
    private long flags;
    private long maxSessionCount;
    private long sessionCount;
    private long maxRwSessionCount;
    private long rwSessionCount;
    private long maxPinLen;
    private long minPinLen;
    private long totalPublicMemory;
    private long freePublicMemory;
    private long totalPrivateMemory;
    private long freePrivateMemory;
    private Version hardwareVersion;
    private Version firmwareVersion;

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getManufacturerID() {
        return manufacturerID;
    }

    public void setManufacturerID(String manufacturerID) {
        this.manufacturerID = manufacturerID;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public long getFlags() {
        return flags;
    }

    public void setFlags(long flags) {
        this.flags = flags;
    }

    public long getMaxSessionCount() {
        return maxSessionCount;
    }

    public void setMaxSessionCount(long maxSessionCount) {
        this.maxSessionCount = maxSessionCount;
    }

    public long getSessionCount() {
        return sessionCount;
    }

    public void setSessionCount(long sessionCount) {
        this.sessionCount = sessionCount;
    }

    public long getMaxRwSessionCount() {
        return maxRwSessionCount;
    }

    public void setMaxRwSessionCount(long maxRwSessionCount) {
        this.maxRwSessionCount = maxRwSessionCount;
    }

    public long getRwSessionCount() {
        return rwSessionCount;
    }

    public void setRwSessionCount(long rwSessionCount) {
        this.rwSessionCount = rwSessionCount;
    }

    public long getMaxPinLen() {
        return maxPinLen;
    }

    public void setMaxPinLen(long maxPinLen) {
        this.maxPinLen = maxPinLen;
    }

    public long getMinPinLen() {
        return minPinLen;
    }

    public void setMinPinLen(long minPinLen) {
        this.minPinLen = minPinLen;
    }

    public long getTotalPublicMemory() {
        return totalPublicMemory;
    }

    public void setTotalPublicMemory(long totalPublicMemory) {
        this.totalPublicMemory = totalPublicMemory;
    }

    public long getFreePublicMemory() {
        return freePublicMemory;
    }

    public void setFreePublicMemory(long freePublicMemory) {
        this.freePublicMemory = freePublicMemory;
    }

    public long getTotalPrivateMemory() {
        return totalPrivateMemory;
    }

    public void setTotalPrivateMemory(long totalPrivateMemory) {
        this.totalPrivateMemory = totalPrivateMemory;
    }

    public long getFreePrivateMemory() {
        return freePrivateMemory;
    }

    public void setFreePrivateMemory(long freePrivateMemory) {
        this.freePrivateMemory = freePrivateMemory;
    }

    public Version getHardwareVersion() {
        return hardwareVersion;
    }

    public void setHardwareVersion(Version hardwareVersion) {
        this.hardwareVersion = hardwareVersion;
    }

    public Version getFirmwareVersion() {
        return firmwareVersion;
    }

    public void setFirmwareVersion(Version firmwareVersion) {
        this.firmwareVersion = firmwareVersion;
    }

    public static class Version implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;
        public int major;
        public int minor;

        public Version(int major, int minor) {
            this.major = major;
            this.minor = minor;
        }

        @Override
        public String toString() {
            return major + "." + minor;
        }
    }
}
