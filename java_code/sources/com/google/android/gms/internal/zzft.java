package com.google.android.gms.internal;

import android.content.Context;
import com.google.android.gms.ads.internal.request.AdResponseParcel;
import com.google.android.gms.internal.zzha;
@zzgd
/* loaded from: classes.dex */
public class zzft {

    /* loaded from: classes.dex */
    public interface zza {
        void zzb(zzha zzhaVar);
    }

    public zzhh zza(Context context, com.google.android.gms.ads.internal.zza zzaVar, zzha.zza zzaVar2, zzan zzanVar, zzid zzidVar, zzef zzefVar, zza zzaVar3) {
        zzhh zzfwVar;
        AdResponseParcel adResponseParcel = zzaVar2.zzFs;
        if (!adResponseParcel.zzsp) {
            zzfwVar = adResponseParcel.zzCK ? new zzfw(context, zzaVar2, zzidVar, zzefVar, zzaVar3) : adResponseParcel.zzCQ ? new zzfr(context, zzaVar2, zzidVar, zzaVar3) : (zzbz.zzuj.get().booleanValue() && zzlk.zzoX() && !zzlk.isAtLeastL() && zzidVar.zzaN().zzsn) ? new zzfv(context, zzaVar2, zzidVar, zzaVar3) : new zzfu(context, zzaVar2, zzidVar, zzaVar3);
        } else if (!(zzaVar instanceof com.google.android.gms.ads.internal.zzm)) {
            throw new IllegalArgumentException("Invalid NativeAdManager type. Found: " + (zzaVar != null ? zzaVar.getClass().getName() : "null") + "; Required: NativeAdManager.");
        } else {
            zzfwVar = new zzfx(context, (com.google.android.gms.ads.internal.zzm) zzaVar, new zzbc(), zzaVar2, zzanVar, zzaVar3);
        }
        zzfwVar.zzgj();
        return zzfwVar;
    }
}
