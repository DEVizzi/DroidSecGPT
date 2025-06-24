package com.google.android.gms.games.internal.constants;
/* loaded from: classes.dex */
public final class PlatformType {
    private PlatformType() {
    }

    public static String zzfG(int i) {
        switch (i) {
            case 0:
                return "ANDROID";
            case 1:
                return "IOS";
            case 2:
                return "WEB_APP";
            default:
                throw new IllegalArgumentException("Unknown platform type: " + i);
        }
    }
}
