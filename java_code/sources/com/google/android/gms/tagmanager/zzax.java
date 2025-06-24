package com.google.android.gms.tagmanager;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
class zzax {
    private static String zzaLU;
    static Map<String, String> zzaLV = new HashMap();

    zzax() {
    }

    static String zzD(String str, String str2) {
        if (str2 == null) {
            if (str.length() > 0) {
                return str;
            }
            return null;
        }
        return Uri.parse("http://hostname/?" + str).getQueryParameter(str2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zzex(String str) {
        synchronized (zzax.class) {
            zzaLU = str;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String zzf(Context context, String str, String str2) {
        String str3 = zzaLV.get(str);
        if (str3 == null) {
            SharedPreferences sharedPreferences = context.getSharedPreferences("gtm_click_referrers", 0);
            str3 = sharedPreferences != null ? sharedPreferences.getString(str, "") : "";
            zzaLV.put(str, str3);
        }
        return zzD(str3, str2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String zzj(Context context, String str) {
        if (zzaLU == null) {
            synchronized (zzax.class) {
                if (zzaLU == null) {
                    SharedPreferences sharedPreferences = context.getSharedPreferences("gtm_install_referrer", 0);
                    if (sharedPreferences != null) {
                        zzaLU = sharedPreferences.getString("referrer", "");
                    } else {
                        zzaLU = "";
                    }
                }
            }
        }
        return zzD(zzaLU, str);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zzk(Context context, String str) {
        String zzD = zzD(str, "conv");
        if (zzD == null || zzD.length() <= 0) {
            return;
        }
        zzaLV.put(zzD, str);
        zzcv.zza(context, "gtm_click_referrers", zzD, str);
    }
}
