package com.google.android.gms.drive.events;

import com.google.android.gms.drive.DriveId;
/* loaded from: classes.dex */
public class zzg {
    public static boolean zza(int i, DriveId driveId) {
        switch (i) {
            case 1:
                return driveId != null;
            case 2:
            case 3:
            default:
                return false;
            case 4:
                return driveId == null;
            case 5:
            case 6:
                return driveId != null;
        }
    }
}
