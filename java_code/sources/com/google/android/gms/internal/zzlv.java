package com.google.android.gms.internal;

import android.content.Context;
import android.content.pm.PackageManager;
import android.telephony.TelephonyManager;
import android.util.Log;
/* loaded from: classes.dex */
public class zzlv {
    private static int zzakU = -1;

    public static boolean zzam(Context context) {
        return zzap(context) == 3;
    }

    private static int zzan(Context context) {
        return ((zzao(context) % 1000) / 100) + 5;
    }

    private static int zzao(Context context) {
        try {
            return context.getPackageManager().getPackageInfo("com.google.android.gms", 0).versionCode;
        } catch (PackageManager.NameNotFoundException e) {
            Log.w("Fitness", "Could not find package info for Google Play Services");
            return -1;
        }
    }

    public static int zzap(Context context) {
        if (zzakU == -1) {
            switch (zzan(context)) {
                case 8:
                case 13:
                    zzakU = 0;
                    break;
                case 9:
                case 11:
                case 12:
                default:
                    zzakU = zzaq(context) ? 1 : 2;
                    break;
                case 10:
                    zzakU = 3;
                    break;
            }
        }
        return zzakU;
    }

    private static boolean zzaq(Context context) {
        return ((TelephonyManager) context.getSystemService("phone")).getPhoneType() != 0;
    }
}
