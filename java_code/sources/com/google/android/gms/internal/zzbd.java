package com.google.android.gms.internal;

import android.content.Context;
import com.google.android.gms.ads.internal.client.AdSizeParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.zzbb;
import com.google.android.gms.internal.zzie;
import org.json.JSONObject;
@zzgd
/* loaded from: classes.dex */
public class zzbd implements zzbb {
    private final zzid zzoA;

    public zzbd(Context context, VersionInfoParcel versionInfoParcel) {
        this.zzoA = com.google.android.gms.ads.internal.zzo.zzbw().zza(context, new AdSizeParcel(), false, false, null, versionInfoParcel);
        this.zzoA.setWillNotDraw(true);
    }

    private void runOnUiThread(Runnable runnable) {
        if (com.google.android.gms.ads.internal.client.zzk.zzcA().zzgw()) {
            runnable.run();
        } else {
            zzhl.zzGk.post(runnable);
        }
    }

    @Override // com.google.android.gms.internal.zzbb
    public void destroy() {
        this.zzoA.destroy();
    }

    @Override // com.google.android.gms.internal.zzbb
    public void zza(com.google.android.gms.ads.internal.client.zza zzaVar, com.google.android.gms.ads.internal.overlay.zzf zzfVar, zzde zzdeVar, com.google.android.gms.ads.internal.overlay.zzk zzkVar, boolean z, zzdi zzdiVar, zzdk zzdkVar, com.google.android.gms.ads.internal.zzd zzdVar, zzev zzevVar) {
        this.zzoA.zzgF().zzb(zzaVar, zzfVar, zzdeVar, zzkVar, z, zzdiVar, zzdkVar, new com.google.android.gms.ads.internal.zzd(false), zzevVar);
    }

    @Override // com.google.android.gms.internal.zzbb
    public void zza(final zzbb.zza zzaVar) {
        this.zzoA.zzgF().zza(new zzie.zza() { // from class: com.google.android.gms.internal.zzbd.6
            @Override // com.google.android.gms.internal.zzie.zza
            public void zza(zzid zzidVar, boolean z) {
                zzaVar.zzcf();
            }
        });
    }

    @Override // com.google.android.gms.internal.zzbe
    public void zza(String str, zzdg zzdgVar) {
        this.zzoA.zzgF().zza(str, zzdgVar);
    }

    @Override // com.google.android.gms.internal.zzbe
    public void zza(final String str, final String str2) {
        runOnUiThread(new Runnable() { // from class: com.google.android.gms.internal.zzbd.2
            @Override // java.lang.Runnable
            public void run() {
                zzbd.this.zzoA.zza(str, str2);
            }
        });
    }

    @Override // com.google.android.gms.internal.zzbe
    public void zza(final String str, final JSONObject jSONObject) {
        runOnUiThread(new Runnable() { // from class: com.google.android.gms.internal.zzbd.1
            @Override // java.lang.Runnable
            public void run() {
                zzbd.this.zzoA.zza(str, jSONObject);
            }
        });
    }

    @Override // com.google.android.gms.internal.zzbe
    public void zzb(String str, zzdg zzdgVar) {
        this.zzoA.zzgF().zzb(str, zzdgVar);
    }

    @Override // com.google.android.gms.internal.zzbb
    public zzbf zzce() {
        return new zzbg(this);
    }

    @Override // com.google.android.gms.internal.zzbb
    public void zzr(String str) {
        final String format = String.format("<!DOCTYPE html><html><head><script src=\"%s\"></script></head><body></body></html>", str);
        runOnUiThread(new Runnable() { // from class: com.google.android.gms.internal.zzbd.3
            @Override // java.lang.Runnable
            public void run() {
                zzbd.this.zzoA.loadData(format, "text/html", "UTF-8");
            }
        });
    }

    @Override // com.google.android.gms.internal.zzbb
    public void zzs(final String str) {
        runOnUiThread(new Runnable() { // from class: com.google.android.gms.internal.zzbd.5
            @Override // java.lang.Runnable
            public void run() {
                zzbd.this.zzoA.loadUrl(str);
            }
        });
    }

    @Override // com.google.android.gms.internal.zzbb
    public void zzt(final String str) {
        runOnUiThread(new Runnable() { // from class: com.google.android.gms.internal.zzbd.4
            @Override // java.lang.Runnable
            public void run() {
                zzbd.this.zzoA.loadData(str, "text/html", "UTF-8");
            }
        });
    }
}
