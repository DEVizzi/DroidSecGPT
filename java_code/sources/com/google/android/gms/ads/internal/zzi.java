package com.google.android.gms.ads.internal;

import android.content.Context;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.client.zzp;
import com.google.android.gms.ads.internal.formats.NativeAdOptionsParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.zzcu;
import com.google.android.gms.internal.zzcv;
import com.google.android.gms.internal.zzcw;
import com.google.android.gms.internal.zzcx;
import com.google.android.gms.internal.zzef;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzkw;
@zzgd
/* loaded from: classes.dex */
public class zzi extends zzp.zza {
    private final Context mContext;
    private com.google.android.gms.ads.internal.client.zzn zzoE;
    private NativeAdOptionsParcel zzoJ;
    private final String zzoL;
    private final VersionInfoParcel zzoM;
    private zzcu zzoP;
    private zzcv zzoQ;
    private final zzef zzoq;
    private zzkw<String, zzcx> zzoS = new zzkw<>();
    private zzkw<String, zzcw> zzoR = new zzkw<>();

    public zzi(Context context, String str, zzef zzefVar, VersionInfoParcel versionInfoParcel) {
        this.mContext = context;
        this.zzoL = str;
        this.zzoq = zzefVar;
        this.zzoM = versionInfoParcel;
    }

    @Override // com.google.android.gms.ads.internal.client.zzp
    public void zza(NativeAdOptionsParcel nativeAdOptionsParcel) {
        this.zzoJ = nativeAdOptionsParcel;
    }

    @Override // com.google.android.gms.ads.internal.client.zzp
    public void zza(zzcu zzcuVar) {
        this.zzoP = zzcuVar;
    }

    @Override // com.google.android.gms.ads.internal.client.zzp
    public void zza(zzcv zzcvVar) {
        this.zzoQ = zzcvVar;
    }

    @Override // com.google.android.gms.ads.internal.client.zzp
    public void zza(String str, zzcx zzcxVar, zzcw zzcwVar) {
        if (TextUtils.isEmpty(str)) {
            throw new IllegalArgumentException("Custom template ID for native custom template ad is empty. Please provide a valid template id.");
        }
        this.zzoS.put(str, zzcxVar);
        this.zzoR.put(str, zzcwVar);
    }

    @Override // com.google.android.gms.ads.internal.client.zzp
    public void zzb(com.google.android.gms.ads.internal.client.zzn zznVar) {
        this.zzoE = zznVar;
    }

    @Override // com.google.android.gms.ads.internal.client.zzp
    public com.google.android.gms.ads.internal.client.zzo zzbi() {
        return new zzh(this.mContext, this.zzoL, this.zzoq, this.zzoM, this.zzoE, this.zzoP, this.zzoQ, this.zzoS, this.zzoR, this.zzoJ);
    }
}
