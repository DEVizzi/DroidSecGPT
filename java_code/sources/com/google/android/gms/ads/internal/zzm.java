package com.google.android.gms.ads.internal;

import android.content.Context;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.AdRequestParcel;
import com.google.android.gms.ads.internal.client.AdSizeParcel;
import com.google.android.gms.ads.internal.formats.NativeAdOptionsParcel;
import com.google.android.gms.ads.internal.formats.zzg;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.internal.zzci;
import com.google.android.gms.internal.zzcu;
import com.google.android.gms.internal.zzcv;
import com.google.android.gms.internal.zzcw;
import com.google.android.gms.internal.zzcx;
import com.google.android.gms.internal.zzef;
import com.google.android.gms.internal.zzff;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzha;
import com.google.android.gms.internal.zzhl;
import com.google.android.gms.internal.zzkw;
import java.util.List;
@zzgd
/* loaded from: classes.dex */
public class zzm extends zzb {
    public zzm(Context context, AdSizeParcel adSizeParcel, String str, zzef zzefVar, VersionInfoParcel versionInfoParcel) {
        super(context, adSizeParcel, str, zzefVar, versionInfoParcel);
    }

    private void zza(final zzha zzhaVar, final String str) {
        zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.ads.internal.zzm.3
            @Override // java.lang.Runnable
            public void run() {
                try {
                    zzm.this.zzon.zzqa.get(str).zza((com.google.android.gms.ads.internal.formats.zzf) zzhaVar.zzFq);
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onCustomTemplateAdLoadedListener.onCustomTemplateAdLoaded().", e);
                }
            }
        });
    }

    private void zzd(final zzha zzhaVar) {
        zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.ads.internal.zzm.1
            @Override // java.lang.Runnable
            public void run() {
                try {
                    zzm.this.zzon.zzpX.zza((com.google.android.gms.ads.internal.formats.zzd) zzhaVar.zzFq);
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call OnAppInstallAdLoadedListener.onAppInstallAdLoaded().", e);
                }
            }
        });
    }

    private void zze(final zzha zzhaVar) {
        zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.ads.internal.zzm.2
            @Override // java.lang.Runnable
            public void run() {
                try {
                    zzm.this.zzon.zzpY.zza((com.google.android.gms.ads.internal.formats.zze) zzhaVar.zzFq);
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call OnContentAdLoadedListener.onContentAdLoaded().", e);
                }
            }
        });
    }

    @Override // com.google.android.gms.ads.internal.zzb, com.google.android.gms.ads.internal.zza, com.google.android.gms.ads.internal.client.zzr
    public void pause() {
        throw new IllegalStateException("Native Ad DOES NOT support pause().");
    }

    @Override // com.google.android.gms.ads.internal.zzb, com.google.android.gms.ads.internal.zza, com.google.android.gms.ads.internal.client.zzr
    public void resume() {
        throw new IllegalStateException("Native Ad DOES NOT support resume().");
    }

    @Override // com.google.android.gms.ads.internal.zzb, com.google.android.gms.ads.internal.client.zzr
    public void showInterstitial() {
        throw new IllegalStateException("Interstitial is NOT supported by NativeAdManager.");
    }

    @Override // com.google.android.gms.ads.internal.zza, com.google.android.gms.ads.internal.client.zzr
    public void zza(zzci zzciVar) {
        throw new IllegalStateException("CustomRendering is NOT supported by NativeAdManager.");
    }

    @Override // com.google.android.gms.ads.internal.zzb, com.google.android.gms.ads.internal.zza, com.google.android.gms.ads.internal.client.zzr
    public void zza(zzff zzffVar) {
        throw new IllegalStateException("In App Purchase is NOT supported by NativeAdManager.");
    }

    public void zza(zzkw<String, zzcx> zzkwVar) {
        zzu.zzbY("setOnCustomTemplateAdLoadedListeners must be called on the main UI thread.");
        this.zzon.zzqa = zzkwVar;
    }

    public void zza(List<String> list) {
        zzu.zzbY("setNativeTemplates must be called on the main UI thread.");
        this.zzon.zzqd = list;
    }

    @Override // com.google.android.gms.ads.internal.zzb
    protected boolean zza(AdRequestParcel adRequestParcel, zzha zzhaVar, boolean z) {
        return this.zzom.zzbp();
    }

    @Override // com.google.android.gms.ads.internal.zzb, com.google.android.gms.ads.internal.zza
    protected boolean zza(zzha zzhaVar, zzha zzhaVar2) {
        zza((List<String>) null);
        if (this.zzon.zzbM()) {
            zzg.zza zzaVar = zzhaVar2.zzFq;
            if ((zzaVar instanceof com.google.android.gms.ads.internal.formats.zze) && this.zzon.zzpY != null) {
                zze(zzhaVar2);
            } else if ((zzaVar instanceof com.google.android.gms.ads.internal.formats.zzd) && this.zzon.zzpX != null) {
                zzd(zzhaVar2);
            } else if (!(zzaVar instanceof com.google.android.gms.ads.internal.formats.zzf) || this.zzon.zzqa == null || this.zzon.zzqa.get(((com.google.android.gms.ads.internal.formats.zzf) zzaVar).getCustomTemplateId()) == null) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("No matching listener for retrieved native ad template.");
                zze(0);
                return false;
            } else {
                zza(zzhaVar2, ((com.google.android.gms.ads.internal.formats.zzf) zzaVar).getCustomTemplateId());
            }
            return super.zza(zzhaVar, zzhaVar2);
        }
        throw new IllegalStateException("Native ad DOES NOT have custom rendering mode.");
    }

    public void zzb(NativeAdOptionsParcel nativeAdOptionsParcel) {
        zzu.zzbY("setNativeAdOptions must be called on the main UI thread.");
        this.zzon.zzqb = nativeAdOptionsParcel;
    }

    public void zzb(zzcu zzcuVar) {
        zzu.zzbY("setOnAppInstallAdLoadedListener must be called on the main UI thread.");
        this.zzon.zzpX = zzcuVar;
    }

    public void zzb(zzcv zzcvVar) {
        zzu.zzbY("setOnContentAdLoadedListener must be called on the main UI thread.");
        this.zzon.zzpY = zzcvVar;
    }

    public void zzb(zzkw<String, zzcw> zzkwVar) {
        zzu.zzbY("setOnCustomClickListener must be called on the main UI thread.");
        this.zzon.zzpZ = zzkwVar;
    }

    @Override // com.google.android.gms.ads.internal.zza
    public boolean zzb(zzha.zza zzaVar) {
        if (zzaVar.zzpN != null) {
            this.zzon.zzpN = zzaVar.zzpN;
        }
        if (zzaVar.errorCode != -2) {
            zzb(new zzha(zzaVar, null, null, null, null, null, null));
            return false;
        }
        this.zzon.zzqh = 0;
        this.zzon.zzpM = zzo.zzbu().zza(this.zzon.zzpH, this, zzaVar, this.zzon.zzpI, null, this.zzoq, this);
        return true;
    }

    public zzkw<String, zzcx> zzbo() {
        zzu.zzbY("getOnCustomTemplateAdLoadedListeners must be called on the main UI thread.");
        return this.zzon.zzqa;
    }

    public zzcw zzq(String str) {
        zzu.zzbY("getOnCustomClickListener must be called on the main UI thread.");
        return this.zzon.zzpZ.get(str);
    }
}
