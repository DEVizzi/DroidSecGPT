package com.google.android.gms.ads.internal.request;

import android.content.Context;
import com.google.android.gms.ads.internal.request.zzd;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzhh;
@zzgd
/* loaded from: classes.dex */
public final class zzc {

    /* loaded from: classes.dex */
    public interface zza {
        void zzb(AdResponseParcel adResponseParcel);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public interface zzb {
        boolean zzd(AdRequestInfoParcel adRequestInfoParcel);
    }

    public static zzhh zza(final Context context, AdRequestInfoParcel adRequestInfoParcel, zza zzaVar) {
        return zza(context, adRequestInfoParcel, zzaVar, new zzb() { // from class: com.google.android.gms.ads.internal.request.zzc.1
            @Override // com.google.android.gms.ads.internal.request.zzc.zzb
            public boolean zzd(AdRequestInfoParcel adRequestInfoParcel2) {
                return adRequestInfoParcel2.zzpJ.zzGJ || GooglePlayServicesUtil.zzae(context);
            }
        });
    }

    static zzhh zza(Context context, AdRequestInfoParcel adRequestInfoParcel, zza zzaVar, zzb zzbVar) {
        return zzbVar.zzd(adRequestInfoParcel) ? zzb(context, adRequestInfoParcel, zzaVar) : zzc(context, adRequestInfoParcel, zzaVar);
    }

    private static zzhh zzb(Context context, AdRequestInfoParcel adRequestInfoParcel, zza zzaVar) {
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Fetching ad response from local ad request service.");
        zzd.zza zzaVar2 = new zzd.zza(context, adRequestInfoParcel, zzaVar);
        zzaVar2.zzgi();
        return zzaVar2;
    }

    private static zzhh zzc(Context context, AdRequestInfoParcel adRequestInfoParcel, zza zzaVar) {
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Fetching ad response from remote ad request service.");
        if (com.google.android.gms.ads.internal.client.zzk.zzcA().zzP(context)) {
            return new zzd.zzb(context, adRequestInfoParcel, zzaVar);
        }
        com.google.android.gms.ads.internal.util.client.zzb.zzaC("Failed to connect to remote ad request service.");
        return null;
    }
}
