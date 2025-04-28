package com.nb.kms.hsm;
import java.io.Serial;
import java.io.Serializable;

public class HsmStatus implements Serializable {
    @Serial
    private static final long serialVersionUID = 2L;
    private String hsmState;
    private String networkStatus;

    public HsmStatus(String hsmState, String networkStatus) {
        this.hsmState = hsmState;
        this.networkStatus = networkStatus;
    }

    public String getHsmState() {
        return hsmState;
    }

    public void setHsmState(String hsmState) {
        this.hsmState = hsmState;
    }

    public String getNetworkStatus() {
        return networkStatus;
    }

    public void setNetworkStatus(String networkStatus) {
        this.networkStatus = networkStatus;
    }

    @Override
    public String toString() {
        return "HsmStatus{" +
                "hsmState='" + hsmState + '\'' +
                ", networkStatus='" + networkStatus + '\'' +
                '}';
    }
}