package com.google.android.gms.analytics.internal;

import android.content.Context;
import com.google.android.gms.analytics.GoogleAnalytics;
import com.google.android.gms.internal.zzlb;
import com.google.android.gms.internal.zzld;
import com.google.android.gms.internal.zzns;
/* loaded from: classes.dex */
public class zzg {
    private final Context zzJR;
    private final Context zzqw;

    public zzg(Context context) {
        com.google.android.gms.common.internal.zzu.zzu(context);
        Context applicationContext = context.getApplicationContext();
        com.google.android.gms.common.internal.zzu.zzb(applicationContext, "Application context can't be null");
        this.zzqw = applicationContext;
        this.zzJR = applicationContext;
    }

    public Context getApplicationContext() {
        return this.zzqw;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public zzns zzW(Context context) {
        return zzns.zzaB(context);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public zzu zza(zzf zzfVar) {
        return new zzu(zzfVar);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public zzk zzb(zzf zzfVar) {
        return new zzk(zzfVar);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public zza zzc(zzf zzfVar) {
        return new zza(zzfVar);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public zzn zzd(zzf zzfVar) {
        return new zzn(zzfVar);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public zzan zze(zzf zzfVar) {
        return new zzan(zzfVar);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public zzaf zzf(zzf zzfVar) {
        return new zzaf(zzfVar);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public zzr zzg(zzf zzfVar) {
        return new zzr(zzfVar);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public zzlb zzh(zzf zzfVar) {
        return zzld.zzoQ();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public GoogleAnalytics zzi(zzf zzfVar) {
        return new GoogleAnalytics(zzfVar);
    }

    public Context zzic() {
        return this.zzJR;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzl zzj(zzf zzfVar) {
        return new zzl(zzfVar, this);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzag zzk(zzf zzfVar) {
        return new zzag(zzfVar);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public zzb zzl(zzf zzfVar) {
        return new zzb(zzfVar, this);
    }

    public zzj zzm(zzf zzfVar) {
        return new zzj(zzfVar);
    }

    public zzah zzn(zzf zzfVar) {
        return new zzah(zzfVar);
    }

    public zzi zzo(zzf zzfVar) {
        return new zzi(zzfVar);
    }

    public zzv zzp(zzf zzfVar) {
        return new zzv(zzfVar);
    }

    public zzai zzq(zzf zzfVar) {
        return new zzai(zzfVar);
    }
}
