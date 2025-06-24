package com.google.android.gms.drive;

import com.google.android.gms.common.api.CommonStatusCodes;
/* loaded from: classes.dex */
public final class DriveStatusCodes extends CommonStatusCodes {
    public static final int DRIVE_CONTENTS_TOO_LARGE = 1508;
    @Deprecated
    public static final int DRIVE_EXTERNAL_STORAGE_REQUIRED = 1500;
    public static final int DRIVE_RATE_LIMIT_EXCEEDED = 1507;
    public static final int DRIVE_RESOURCE_NOT_AVAILABLE = 1502;

    private DriveStatusCodes() {
    }

    public static String getStatusCodeString(int statusCode) {
        switch (statusCode) {
            case 1500:
                return "DRIVE_EXTERNAL_STORAGE_REQUIRED";
            case DRIVE_RESOURCE_NOT_AVAILABLE /* 1502 */:
                return "DRIVE_RESOURCE_NOT_AVAILABLE";
            case DRIVE_RATE_LIMIT_EXCEEDED /* 1507 */:
                return "DRIVE_RATE_LIMIT_EXCEEDED";
            default:
                return CommonStatusCodes.getStatusCodeString(statusCode);
        }
    }
}
