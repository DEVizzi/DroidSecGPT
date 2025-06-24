package com.google.android.gms.wearable;

import java.io.IOException;
/* loaded from: classes.dex */
public class ChannelIOException extends IOException {
    private final int zzaSO;
    private final int zzaSP;

    public ChannelIOException(String message, int closeReason, int appSpecificErrorCode) {
        super(message);
        this.zzaSO = closeReason;
        this.zzaSP = appSpecificErrorCode;
    }

    public int getAppSpecificErrorCode() {
        return this.zzaSP;
    }

    public int getCloseReason() {
        return this.zzaSO;
    }
}
