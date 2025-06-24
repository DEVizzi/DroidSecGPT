package com.google.android.gms.internal;

import com.google.android.gms.ads.internal.request.AdRequestInfoParcel;
import com.google.android.gms.ads.internal.request.AdResponseParcel;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
@zzgd
/* loaded from: classes.dex */
public final class zzgi {
    private List<String> zzBK;
    private String zzDR;
    private String zzDS;
    private List<String> zzDT;
    private String zzDU;
    private String zzDV;
    private List<String> zzDW;
    private String zzvj;
    private final AdRequestInfoParcel zzxm;
    private long zzDX = -1;
    private boolean zzDY = false;
    private final long zzDZ = -1;
    private long zzEa = -1;
    private int mOrientation = -1;
    private boolean zzEb = false;
    private boolean zzEc = false;
    private boolean zzEd = false;
    private boolean zzEe = true;
    private int zzEf = 0;

    public zzgi(AdRequestInfoParcel adRequestInfoParcel) {
        this.zzxm = adRequestInfoParcel;
    }

    static String zzc(Map<String, List<String>> map, String str) {
        List<String> list = map.get(str);
        if (list == null || list.isEmpty()) {
            return null;
        }
        return list.get(0);
    }

    static long zzd(Map<String, List<String>> map, String str) {
        List<String> list = map.get(str);
        if (list != null && !list.isEmpty()) {
            String str2 = list.get(0);
            try {
                return Float.parseFloat(str2) * 1000.0f;
            } catch (NumberFormatException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Could not parse float from " + str + " header: " + str2);
            }
        }
        return -1L;
    }

    static List<String> zze(Map<String, List<String>> map, String str) {
        String str2;
        List<String> list = map.get(str);
        if (list == null || list.isEmpty() || (str2 = list.get(0)) == null) {
            return null;
        }
        return Arrays.asList(str2.trim().split("\\s+"));
    }

    private boolean zzf(Map<String, List<String>> map, String str) {
        List<String> list = map.get(str);
        return (list == null || list.isEmpty() || !Boolean.valueOf(list.get(0)).booleanValue()) ? false : true;
    }

    private void zzj(Map<String, List<String>> map) {
        this.zzDR = zzc(map, "X-Afma-Ad-Size");
    }

    private void zzk(Map<String, List<String>> map) {
        List<String> zze = zze(map, "X-Afma-Click-Tracking-Urls");
        if (zze != null) {
            this.zzDT = zze;
        }
    }

    private void zzl(Map<String, List<String>> map) {
        List<String> list = map.get("X-Afma-Debug-Dialog");
        if (list == null || list.isEmpty()) {
            return;
        }
        this.zzDU = list.get(0);
    }

    private void zzm(Map<String, List<String>> map) {
        List<String> zze = zze(map, "X-Afma-Tracking-Urls");
        if (zze != null) {
            this.zzDW = zze;
        }
    }

    private void zzn(Map<String, List<String>> map) {
        long zzd = zzd(map, "X-Afma-Interstitial-Timeout");
        if (zzd != -1) {
            this.zzDX = zzd;
        }
    }

    private void zzo(Map<String, List<String>> map) {
        this.zzDV = zzc(map, "X-Afma-ActiveView");
    }

    private void zzp(Map<String, List<String>> map) {
        this.zzEc = ((this.zzxm == null || this.zzxm.zzCs == 0) ? false : true) | this.zzEc;
    }

    private void zzq(Map<String, List<String>> map) {
        this.zzEb |= zzf(map, "X-Afma-Custom-Rendering-Allowed");
    }

    private void zzr(Map<String, List<String>> map) {
        this.zzDY |= zzf(map, "X-Afma-Mediation");
    }

    private void zzs(Map<String, List<String>> map) {
        List<String> zze = zze(map, "X-Afma-Manual-Tracking-Urls");
        if (zze != null) {
            this.zzBK = zze;
        }
    }

    private void zzt(Map<String, List<String>> map) {
        long zzd = zzd(map, "X-Afma-Refresh-Rate");
        if (zzd != -1) {
            this.zzEa = zzd;
        }
    }

    private void zzu(Map<String, List<String>> map) {
        List<String> list = map.get("X-Afma-Orientation");
        if (list == null || list.isEmpty()) {
            return;
        }
        String str = list.get(0);
        if ("portrait".equalsIgnoreCase(str)) {
            this.mOrientation = com.google.android.gms.ads.internal.zzo.zzbx().zzgr();
        } else if ("landscape".equalsIgnoreCase(str)) {
            this.mOrientation = com.google.android.gms.ads.internal.zzo.zzbx().zzgq();
        }
    }

    private void zzv(Map<String, List<String>> map) {
        List<String> list = map.get("X-Afma-Use-HTTPS");
        if (list == null || list.isEmpty()) {
            return;
        }
        this.zzEd = Boolean.valueOf(list.get(0)).booleanValue();
    }

    private void zzw(Map<String, List<String>> map) {
        List<String> list = map.get("X-Afma-Content-Url-Opted-Out");
        if (list == null || list.isEmpty()) {
            return;
        }
        this.zzEe = Boolean.valueOf(list.get(0)).booleanValue();
    }

    private void zzx(Map<String, List<String>> map) {
        List<String> zze = zze(map, "X-Afma-OAuth-Token-Status");
        this.zzEf = 0;
        if (zze == null) {
            return;
        }
        for (String str : zze) {
            if ("Clear".equalsIgnoreCase(str)) {
                this.zzEf = 1;
                return;
            } else if ("No-Op".equalsIgnoreCase(str)) {
                this.zzEf = 0;
                return;
            }
        }
    }

    public void zza(String str, Map<String, List<String>> map, String str2) {
        this.zzDS = str;
        this.zzvj = str2;
        zzi(map);
    }

    public void zzi(Map<String, List<String>> map) {
        zzj(map);
        zzk(map);
        zzl(map);
        zzm(map);
        zzn(map);
        zzr(map);
        zzs(map);
        zzt(map);
        zzu(map);
        zzo(map);
        zzv(map);
        zzq(map);
        zzp(map);
        zzw(map);
        zzx(map);
    }

    public AdResponseParcel zzj(long j) {
        return new AdResponseParcel(this.zzxm, this.zzDS, this.zzvj, this.zzDT, this.zzDW, this.zzDX, this.zzDY, -1L, this.zzBK, this.zzEa, this.mOrientation, this.zzDR, j, this.zzDU, this.zzDV, this.zzEb, this.zzEc, this.zzEd, this.zzEe, false, this.zzEf);
    }
}
