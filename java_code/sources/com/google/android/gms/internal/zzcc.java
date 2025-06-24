package com.google.android.gms.internal;

import android.text.TextUtils;
/* loaded from: classes.dex */
public class zzcc {
    private boolean zzuy = false;

    private zzcb zzb(zzca zzcaVar, int i) {
        zzcb zzcbVar = new zzcb(zzcaVar.getContext(), zzcaVar.zzbR(), zzcaVar.zzdd(), zzcaVar.zzde(), zzcaVar.zzdf(), zzcaVar.zzdg(), zzcaVar.zzdh(), zzcaVar.zzdi(), i);
        this.zzuy = true;
        return zzcbVar;
    }

    public zzcb zza(zzca zzcaVar) {
        return zza(zzcaVar, 1);
    }

    public zzcb zza(zzca zzcaVar, int i) {
        if (zzcaVar == null) {
            throw new IllegalArgumentException("CSI configuration can't be null. ");
        }
        if (!zzcaVar.zzdc()) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaA("CsiReporterFactory: CSI is not enabled. No CSI reporter created.");
            return null;
        } else if (zzcaVar.getContext() == null) {
            throw new IllegalArgumentException("Context can't be null. Please set up context in CsiConfiguration.");
        } else {
            if (TextUtils.isEmpty(zzcaVar.zzbR())) {
                throw new IllegalArgumentException("AfmaVersion can't be null or empty. Please set up afmaVersion in CsiConfiguration.");
            }
            return zzb(zzcaVar, i);
        }
    }

    public zzcb zzb(zzca zzcaVar) {
        return zza(zzcaVar, 2);
    }

    public boolean zzdc() {
        return this.zzuy;
    }
}
