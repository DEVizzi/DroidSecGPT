package com.google.android.gms.ads.internal;

import android.content.Context;
import com.google.android.gms.ads.internal.client.AdRequestParcel;
import com.google.android.gms.ads.internal.client.AdSizeParcel;
import com.google.android.gms.ads.internal.client.zzo;
import com.google.android.gms.ads.internal.formats.NativeAdOptionsParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.zzcu;
import com.google.android.gms.internal.zzcv;
import com.google.android.gms.internal.zzcw;
import com.google.android.gms.internal.zzcx;
import com.google.android.gms.internal.zzef;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzhl;
import com.google.android.gms.internal.zzkw;
import java.util.ArrayList;
import java.util.List;
@zzgd
/* loaded from: classes.dex */
public class zzh extends zzo.zza {
    private final Context mContext;
    private final com.google.android.gms.ads.internal.client.zzn zzoE;
    private final zzcu zzoF;
    private final zzcv zzoG;
    private final zzkw<String, zzcx> zzoH;
    private final zzkw<String, zzcw> zzoI;
    private final NativeAdOptionsParcel zzoJ;
    private final List<String> zzoK = zzbg();
    private final String zzoL;
    private final VersionInfoParcel zzoM;
    private final zzef zzoq;

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzh(Context context, String str, zzef zzefVar, VersionInfoParcel versionInfoParcel, com.google.android.gms.ads.internal.client.zzn zznVar, zzcu zzcuVar, zzcv zzcvVar, zzkw<String, zzcx> zzkwVar, zzkw<String, zzcw> zzkwVar2, NativeAdOptionsParcel nativeAdOptionsParcel) {
        this.mContext = context;
        this.zzoL = str;
        this.zzoq = zzefVar;
        this.zzoM = versionInfoParcel;
        this.zzoE = zznVar;
        this.zzoG = zzcvVar;
        this.zzoF = zzcuVar;
        this.zzoH = zzkwVar;
        this.zzoI = zzkwVar2;
        this.zzoJ = nativeAdOptionsParcel;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public List<String> zzbg() {
        ArrayList arrayList = new ArrayList();
        if (this.zzoG != null) {
            arrayList.add("1");
        }
        if (this.zzoF != null) {
            arrayList.add("2");
        }
        if (this.zzoH.size() > 0) {
            arrayList.add("3");
        }
        return arrayList;
    }

    protected void runOnUiThread(Runnable runnable) {
        zzhl.zzGk.post(runnable);
    }

    protected zzm zzbh() {
        return new zzm(this.mContext, AdSizeParcel.zzs(this.mContext), this.zzoL, this.zzoq, this.zzoM);
    }

    @Override // com.google.android.gms.ads.internal.client.zzo
    public void zze(final AdRequestParcel adRequestParcel) {
        runOnUiThread(new Runnable() { // from class: com.google.android.gms.ads.internal.zzh.1
            @Override // java.lang.Runnable
            public void run() {
                zzm zzbh = zzh.this.zzbh();
                zzbh.zzb(zzh.this.zzoF);
                zzbh.zzb(zzh.this.zzoG);
                zzbh.zza(zzh.this.zzoH);
                zzbh.zza(zzh.this.zzoE);
                zzbh.zzb(zzh.this.zzoI);
                zzbh.zza(zzh.this.zzbg());
                zzbh.zzb(zzh.this.zzoJ);
                zzbh.zza(adRequestParcel);
            }
        });
    }
}
