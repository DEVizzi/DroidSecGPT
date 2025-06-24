package com.google.android.gms.tagmanager;

import android.os.Build;
import java.io.File;
/* loaded from: classes.dex */
class zzal {
    public static int version() {
        try {
            return Integer.parseInt(Build.VERSION.SDK);
        } catch (NumberFormatException e) {
            zzbg.zzaz("Invalid version number: " + Build.VERSION.SDK);
            return 0;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean zzbe(String str) {
        if (version() < 9) {
            return false;
        }
        File file = new File(str);
        file.setReadable(false, false);
        file.setWritable(false, false);
        file.setReadable(true, true);
        file.setWritable(true, true);
        return true;
    }
}
