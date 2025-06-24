package com.google.android.gms.internal;

import android.content.res.Configuration;
import android.content.res.Resources;
/* loaded from: classes.dex */
public final class zzle {
    public static boolean zzb(Resources resources) {
        if (resources == null) {
            return false;
        }
        return (zzlk.zzoR() && ((resources.getConfiguration().screenLayout & 15) > 3)) || zzc(resources);
    }

    private static boolean zzc(Resources resources) {
        Configuration configuration = resources.getConfiguration();
        return zzlk.zzoT() && (configuration.screenLayout & 15) <= 3 && configuration.smallestScreenWidthDp >= 600;
    }
}
