package com.google.android.gms.internal;

import java.util.HashMap;
import java.util.Map;
@zzgd
/* loaded from: classes.dex */
public class zzdm implements zzdg {
    static final Map<String, Integer> zzwy = new HashMap();
    private final com.google.android.gms.ads.internal.zzd zzww;
    private final zzep zzwx;

    static {
        zzwy.put("resize", 1);
        zzwy.put("playVideo", 2);
        zzwy.put("storePicture", 3);
        zzwy.put("createCalendarEvent", 4);
        zzwy.put("setOrientationProperties", 5);
        zzwy.put("closeResizedAd", 6);
    }

    public zzdm(com.google.android.gms.ads.internal.zzd zzdVar, zzep zzepVar) {
        this.zzww = zzdVar;
        this.zzwx = zzepVar;
    }

    @Override // com.google.android.gms.internal.zzdg
    public void zza(zzid zzidVar, Map<String, String> map) {
        int intValue = zzwy.get(map.get("a")).intValue();
        if (intValue != 5 && this.zzww != null && !this.zzww.zzbd()) {
            this.zzww.zzo(null);
            return;
        }
        switch (intValue) {
            case 1:
                this.zzwx.zzh(map);
                return;
            case 2:
            default:
                com.google.android.gms.ads.internal.util.client.zzb.zzaA("Unknown MRAID command called.");
                return;
            case 3:
                new zzer(zzidVar, map).execute();
                return;
            case 4:
                new zzeo(zzidVar, map).execute();
                return;
            case 5:
                new zzeq(zzidVar, map).execute();
                return;
            case 6:
                this.zzwx.zzn(true);
                return;
        }
    }
}
