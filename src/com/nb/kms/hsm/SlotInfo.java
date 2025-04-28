package com.nb.kms.hsm;

import java.io.Serial;
import java.io.Serializable;

// HSM Slot Info 클래스를 생성하여 C_GetSlotInfo 결과를 담을 수 있게 함
public class SlotInfo implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private String slotDescription;
    private String manufacturerID;
    private long flags;
    private Version hardwareVersion;
    private Version firmwareVersion;

    public String getSlotDescription() {
        return slotDescription;
    }

    public void setSlotDescription(String slotDescription) {
        this.slotDescription = slotDescription;
    }

    public String getManufacturerID() {
        return manufacturerID;
    }

    public void setManufacturerID(String manufacturerID) {
        this.manufacturerID = manufacturerID;
    }

    public long getFlags() {
        return flags;
    }

    public void setFlags(long flags) {
        this.flags = flags;
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