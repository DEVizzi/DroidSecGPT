package com.google.android.gms.appdatasearch;

import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
public class zzh {
    private static final String[] zzNq = {"text1", "text2", "icon", "intent_action", "intent_data", "intent_data_id", "intent_extra_data", "suggest_large_icon", "intent_activity"};
    private static final Map<String, Integer> zzNr = new HashMap(zzNq.length);

    static {
        for (int i = 0; i < zzNq.length; i++) {
            zzNr.put(zzNq[i], Integer.valueOf(i));
        }
    }

    public static String zzai(int i) {
        if (i < 0 || i >= zzNq.length) {
            return null;
        }
        return zzNq[i];
    }

    public static int zzbq(String str) {
        Integer num = zzNr.get(str);
        if (num == null) {
            throw new IllegalArgumentException("[" + str + "] is not a valid global search section name");
        }
        return num.intValue();
    }

    public static int zzkL() {
        return zzNq.length;
    }
}
