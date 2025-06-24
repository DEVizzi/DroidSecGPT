package com.google.android.gms.internal;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Map;
/* loaded from: classes.dex */
public class zzce {
    private static int zzuP;
    private final Object zzqt = new Object();
    final String zzuO;
    private final LinkedList<zzcd> zzuQ;
    private zzcd zzuR;

    public zzce(String str) {
        this.zzuO = str;
        zzuP = zzbz.zztZ.get().intValue();
        synchronized (this.zzqt) {
            this.zzuQ = new LinkedList<>();
        }
    }

    private static Map<String, String> zza(String str, StringBuilder sb) {
        LinkedHashMap linkedHashMap = null;
        if (sb.length() > 0) {
            linkedHashMap = new LinkedHashMap();
            if (str != null) {
                linkedHashMap.put("action", str);
            }
            sb.setLength(sb.length() - 1);
            linkedHashMap.put("it", sb.toString());
        }
        return linkedHashMap;
    }

    public static Map<String, String> zza(zzce... zzceVarArr) throws IllegalArgumentException {
        String str = null;
        StringBuilder sb = new StringBuilder(zzuP * 10 * 20);
        int i = 0;
        while (true) {
            int i2 = i;
            if (i2 >= zzceVarArr.length) {
                return zza(str, sb);
            }
            Map<String, String> zzdq = zzceVarArr[i2].zzdq();
            if (zzdq != null) {
                if (i2 == 0) {
                    str = zzdq.get("action");
                    sb.append(zzdq.get("it")).append(",");
                } else if ((zzdq.containsKey("action") || str == null) && (!zzdq.containsKey("action") || zzdq.get("action").equals(str))) {
                    sb.append(zzdq.get("it")).append(",");
                }
            }
            i = i2 + 1;
        }
        throw new IllegalArgumentException("Can not merge report items for the tickers with different action names.");
    }

    private boolean zza(zzcd zzcdVar, long j, String... strArr) {
        synchronized (this.zzqt) {
            for (String str : strArr) {
                this.zzuQ.add(new zzcd(j, str, zzcdVar));
            }
        }
        return true;
    }

    private zzcd zzb(long j) {
        return new zzcd(j, null, null);
    }

    public boolean zza(zzcd zzcdVar, String... strArr) {
        if (!com.google.android.gms.ads.internal.zzo.zzbA().zzdc() || zzcdVar == null) {
            return false;
        }
        return zza(zzcdVar, com.google.android.gms.ads.internal.zzo.zzbz().elapsedRealtime(), strArr);
    }

    public zzcd zzdo() {
        if (com.google.android.gms.ads.internal.zzo.zzbA().zzdc()) {
            return zzb(com.google.android.gms.ads.internal.zzo.zzbz().elapsedRealtime());
        }
        return null;
    }

    public void zzdp() {
        this.zzuR = zzdo();
    }

    Map<String, String> zzdq() {
        StringBuilder sb = new StringBuilder();
        synchronized (this.zzqt) {
            Iterator<zzcd> it = this.zzuQ.iterator();
            while (it.hasNext()) {
                zzcd next = it.next();
                Long valueOf = Long.valueOf(next.getTime());
                String zzdm = next.zzdm();
                zzcd zzdn = next.zzdn();
                if (zzdn != null && valueOf.longValue() > 0) {
                    sb.append(zzdm).append('.').append(valueOf.longValue() - zzdn.getTime()).append(',');
                }
            }
            this.zzuQ.clear();
        }
        return zza(this.zzuO, sb);
    }

    public String zzdr() {
        return this.zzuO;
    }

    public zzcd zzds() {
        return this.zzuR;
    }
}
