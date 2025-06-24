package com.google.android.gms.internal;

import android.text.TextUtils;
import com.google.android.gms.ads.internal.overlay.AdLauncherIntentInfoParcel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
@zzgd
/* loaded from: classes.dex */
public final class zzdn implements zzdg {
    private final com.google.android.gms.ads.internal.zzd zzww;
    private final zzep zzwx;
    private final zzdi zzwz;

    public zzdn(zzdi zzdiVar, com.google.android.gms.ads.internal.zzd zzdVar, zzep zzepVar) {
        this.zzwz = zzdiVar;
        this.zzww = zzdVar;
        this.zzwx = zzepVar;
    }

    private static boolean zzd(Map<String, String> map) {
        return "1".equals(map.get("custom_close"));
    }

    private static int zze(Map<String, String> map) {
        String str = map.get("o");
        if (str != null) {
            if ("p".equalsIgnoreCase(str)) {
                return com.google.android.gms.ads.internal.zzo.zzbx().zzgr();
            }
            if ("l".equalsIgnoreCase(str)) {
                return com.google.android.gms.ads.internal.zzo.zzbx().zzgq();
            }
            if ("c".equalsIgnoreCase(str)) {
                return com.google.android.gms.ads.internal.zzo.zzbx().zzgs();
            }
        }
        return -1;
    }

    private void zzm(boolean z) {
        if (this.zzwx != null) {
            this.zzwx.zzn(z);
        }
    }

    @Override // com.google.android.gms.internal.zzdg
    public void zza(zzid zzidVar, Map<String, String> map) {
        String str = map.get("a");
        if (str == null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Action missing from an open GMSG.");
        } else if (this.zzww != null && !this.zzww.zzbd()) {
            this.zzww.zzo(map.get("u"));
        } else {
            zzie zzgF = zzidVar.zzgF();
            if ("expand".equalsIgnoreCase(str)) {
                if (zzidVar.zzgJ()) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzaC("Cannot expand WebView that is already expanded.");
                    return;
                }
                zzm(false);
                zzgF.zza(zzd(map), zze(map));
            } else if ("webapp".equalsIgnoreCase(str)) {
                String str2 = map.get("u");
                zzm(false);
                if (str2 != null) {
                    zzgF.zza(zzd(map), zze(map), str2);
                } else {
                    zzgF.zza(zzd(map), zze(map), map.get("html"), map.get("baseurl"));
                }
            } else if (!"in_app_purchase".equalsIgnoreCase(str)) {
                zzm(true);
                zzidVar.zzgH();
                String str3 = map.get("u");
                zzgF.zza(new AdLauncherIntentInfoParcel(map.get("i"), !TextUtils.isEmpty(str3) ? com.google.android.gms.ads.internal.zzo.zzbv().zza(zzidVar, str3) : str3, map.get("m"), map.get("p"), map.get("c"), map.get("f"), map.get("e")));
            } else {
                String str4 = map.get("product_id");
                String str5 = map.get("report_urls");
                if (this.zzwz != null) {
                    if (str5 == null || str5.isEmpty()) {
                        this.zzwz.zza(str4, new ArrayList<>());
                    } else {
                        this.zzwz.zza(str4, new ArrayList<>(Arrays.asList(str5.split(" "))));
                    }
                }
            }
        }
    }
}
