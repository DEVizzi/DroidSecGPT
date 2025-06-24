package com.google.android.gms.ads.internal;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.DisplayMetrics;
import com.google.android.gms.ads.internal.client.AdRequestParcel;
import com.google.android.gms.ads.internal.client.AdSizeParcel;
import com.google.android.gms.ads.internal.purchase.GInAppPurchaseManagerInfoParcel;
import com.google.android.gms.ads.internal.request.AdRequestInfoParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.internal.zzbz;
import com.google.android.gms.internal.zzdi;
import com.google.android.gms.internal.zzdz;
import com.google.android.gms.internal.zzef;
import com.google.android.gms.internal.zzfc;
import com.google.android.gms.internal.zzff;
import com.google.android.gms.internal.zzfj;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzha;
import com.google.android.gms.internal.zzhb;
import com.google.android.gms.internal.zzhl;
import java.util.ArrayList;
import java.util.UUID;
@zzgd
/* loaded from: classes.dex */
public abstract class zzb extends zza implements com.google.android.gms.ads.internal.overlay.zzf, com.google.android.gms.ads.internal.purchase.zzj, zzdi, zzdz {
    private final Messenger mMessenger;
    protected final zzef zzoq;
    protected transient boolean zzor;

    public zzb(Context context, AdSizeParcel adSizeParcel, String str, zzef zzefVar, VersionInfoParcel versionInfoParcel) {
        this(new zzp(context, adSizeParcel, str, versionInfoParcel), zzefVar, null);
    }

    zzb(zzp zzpVar, zzef zzefVar, zzn zznVar) {
        super(zzpVar, zznVar);
        this.zzoq = zzefVar;
        this.mMessenger = new Messenger(new zzfc(this.zzon.zzpH));
        this.zzor = false;
    }

    private AdRequestInfoParcel.zza zza(AdRequestParcel adRequestParcel, Bundle bundle) {
        PackageInfo packageInfo;
        ApplicationInfo applicationInfo = this.zzon.zzpH.getApplicationInfo();
        try {
            packageInfo = this.zzon.zzpH.getPackageManager().getPackageInfo(applicationInfo.packageName, 0);
        } catch (PackageManager.NameNotFoundException e) {
            packageInfo = null;
        }
        DisplayMetrics displayMetrics = this.zzon.zzpH.getResources().getDisplayMetrics();
        Bundle bundle2 = null;
        if (this.zzon.zzpK != null && this.zzon.zzpK.getParent() != null) {
            int[] iArr = new int[2];
            this.zzon.zzpK.getLocationOnScreen(iArr);
            int i = iArr[0];
            int i2 = iArr[1];
            int width = this.zzon.zzpK.getWidth();
            int height = this.zzon.zzpK.getHeight();
            int i3 = 0;
            if (this.zzon.zzpK.isShown() && i + width > 0 && i2 + height > 0 && i <= displayMetrics.widthPixels && i2 <= displayMetrics.heightPixels) {
                i3 = 1;
            }
            bundle2 = new Bundle(5);
            bundle2.putInt("x", i);
            bundle2.putInt("y", i2);
            bundle2.putInt("width", width);
            bundle2.putInt("height", height);
            bundle2.putInt("visible", i3);
        }
        String zzfW = zzo.zzby().zzfW();
        this.zzon.zzpQ = new zzhb(zzfW, this.zzon.zzpG);
        this.zzon.zzpQ.zzh(adRequestParcel);
        String zza = zzo.zzbv().zza(this.zzon.zzpH, this.zzon.zzpK, this.zzon.zzpN);
        int zzbn = zzl.zzq(this.zzon.zzpH).zzbn();
        boolean zzbl = zzl.zzq(this.zzon.zzpH).zzbl();
        long j = 0;
        if (this.zzon.zzpU != null) {
            try {
                j = this.zzon.zzpU.getValue();
            } catch (RemoteException e2) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Cannot get correlation id, default to 0.");
            }
        }
        String uuid = UUID.randomUUID().toString();
        Bundle zza2 = zzo.zzby().zza(this.zzon.zzpH, this, zzfW);
        ArrayList arrayList = new ArrayList();
        for (int i4 = 0; i4 < this.zzon.zzqa.size(); i4++) {
            arrayList.add(this.zzon.zzqa.keyAt(i4));
        }
        return new AdRequestInfoParcel.zza(bundle2, adRequestParcel, this.zzon.zzpN, this.zzon.zzpG, applicationInfo, packageInfo, zzfW, zzo.zzby().getSessionId(), this.zzon.zzpJ, zza2, this.zzon.zzqd, arrayList, bundle, zzo.zzby().zzga(), this.mMessenger, displayMetrics.widthPixels, displayMetrics.heightPixels, displayMetrics.density, zza, zzbl, zzbn, j, uuid, zzbz.zzdb(), this.zzon.zzpF, this.zzon.zzqb);
    }

    @Override // com.google.android.gms.ads.internal.client.zzr
    public String getMediationAdapterClassName() {
        if (this.zzon.zzpO == null) {
            return null;
        }
        return this.zzon.zzpO.zzyb;
    }

    @Override // com.google.android.gms.ads.internal.zza, com.google.android.gms.ads.internal.client.zza
    public void onAdClicked() {
        if (this.zzon.zzpO == null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Ad state was null when trying to ping click URLs.");
            return;
        }
        if (this.zzon.zzpO.zzFm != null && this.zzon.zzpO.zzFm.zzxF != null) {
            zzo.zzbG().zza(this.zzon.zzpH, this.zzon.zzpJ.zzGG, this.zzon.zzpO, this.zzon.zzpG, false, zza(this.zzon.zzpO.zzFm.zzxF, this.zzon.zzpO.zzCC));
        }
        if (this.zzon.zzpO.zzxZ != null && this.zzon.zzpO.zzxZ.zzxx != null) {
            zzo.zzbG().zza(this.zzon.zzpH, this.zzon.zzpJ.zzGG, this.zzon.zzpO, this.zzon.zzpG, false, this.zzon.zzpO.zzxZ.zzxx);
        }
        super.onAdClicked();
    }

    @Override // com.google.android.gms.ads.internal.zza, com.google.android.gms.ads.internal.client.zzr
    public void pause() {
        zzu.zzbY("pause must be called on the main UI thread.");
        if (this.zzon.zzpO != null && this.zzon.zzbM()) {
            zzo.zzbx().zza(this.zzon.zzpO.zzzE.getWebView());
        }
        if (this.zzon.zzpO != null && this.zzon.zzpO.zzya != null) {
            try {
                this.zzon.zzpO.zzya.pause();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Could not pause mediation adapter.");
            }
        }
        this.zzop.zzi(this.zzon.zzpO);
        this.zzom.pause();
    }

    @Override // com.google.android.gms.ads.internal.zza, com.google.android.gms.ads.internal.client.zzr
    public void resume() {
        zzu.zzbY("resume must be called on the main UI thread.");
        if (this.zzon.zzpO != null && this.zzon.zzbM()) {
            zzo.zzbx().zzb(this.zzon.zzpO.zzzE.getWebView());
        }
        if (this.zzon.zzpO != null && this.zzon.zzpO.zzya != null) {
            try {
                this.zzon.zzpO.zzya.resume();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Could not resume mediation adapter.");
            }
        }
        this.zzom.resume();
        this.zzop.zzj(this.zzon.zzpO);
    }

    @Override // com.google.android.gms.ads.internal.client.zzr
    public void showInterstitial() {
        throw new IllegalStateException("showInterstitial is not supported for current ad type");
    }

    @Override // com.google.android.gms.ads.internal.zza, com.google.android.gms.ads.internal.client.zzr
    public void zza(zzff zzffVar) {
        zzu.zzbY("setInAppPurchaseListener must be called on the main UI thread.");
        this.zzon.zzpV = zzffVar;
    }

    @Override // com.google.android.gms.ads.internal.zza, com.google.android.gms.ads.internal.client.zzr
    public void zza(zzfj zzfjVar, String str) {
        zzu.zzbY("setPlayStorePurchaseParams must be called on the main UI thread.");
        this.zzon.zzqe = new com.google.android.gms.ads.internal.purchase.zzk(str);
        this.zzon.zzpW = zzfjVar;
        if (zzo.zzby().zzfZ() || zzfjVar == null) {
            return;
        }
        new com.google.android.gms.ads.internal.purchase.zzc(this.zzon.zzpH, this.zzon.zzpW, this.zzon.zzqe).zzgi();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void zza(zzha zzhaVar, boolean z) {
        if (zzhaVar == null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Ad state was null when trying to ping impression URLs.");
            return;
        }
        super.zzc(zzhaVar);
        if (zzhaVar.zzFm != null && zzhaVar.zzFm.zzxG != null) {
            zzo.zzbG().zza(this.zzon.zzpH, this.zzon.zzpJ.zzGG, zzhaVar, this.zzon.zzpG, z, zza(zzhaVar.zzFm.zzxG, zzhaVar.zzCC));
        }
        if (zzhaVar.zzxZ == null || zzhaVar.zzxZ.zzxy == null) {
            return;
        }
        zzo.zzbG().zza(this.zzon.zzpH, this.zzon.zzpJ.zzGG, zzhaVar, this.zzon.zzpG, z, zzhaVar.zzxZ.zzxy);
    }

    @Override // com.google.android.gms.internal.zzdi
    public void zza(String str, ArrayList<String> arrayList) {
        com.google.android.gms.ads.internal.purchase.zzd zzdVar = new com.google.android.gms.ads.internal.purchase.zzd(str, arrayList, this.zzon.zzpH, this.zzon.zzpJ.zzGG);
        if (this.zzon.zzpV != null) {
            try {
                this.zzon.zzpV.zza(zzdVar);
                return;
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Could not start In-App purchase.");
                return;
            }
        }
        com.google.android.gms.ads.internal.util.client.zzb.zzaC("InAppPurchaseListener is not set. Try to launch default purchase flow.");
        if (!com.google.android.gms.ads.internal.client.zzk.zzcA().zzP(this.zzon.zzpH)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Google Play Service unavailable, cannot launch default purchase flow.");
        } else if (this.zzon.zzpW == null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("PlayStorePurchaseListener is not set.");
        } else if (this.zzon.zzqe == null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("PlayStorePurchaseVerifier is not initialized.");
        } else if (this.zzon.zzqi) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("An in-app purchase request is already in progress, abort");
        } else {
            this.zzon.zzqi = true;
            try {
                if (this.zzon.zzpW.isValidPurchase(str)) {
                    zzo.zzbF().zza(this.zzon.zzpH, this.zzon.zzpJ.zzGJ, new GInAppPurchaseManagerInfoParcel(this.zzon.zzpH, this.zzon.zzqe, zzdVar, this));
                } else {
                    this.zzon.zzqi = false;
                }
            } catch (RemoteException e2) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Could not start In-App purchase.");
                this.zzon.zzqi = false;
            }
        }
    }

    @Override // com.google.android.gms.ads.internal.purchase.zzj
    public void zza(String str, boolean z, int i, final Intent intent, com.google.android.gms.ads.internal.purchase.zzf zzfVar) {
        try {
            if (this.zzon.zzpW != null) {
                this.zzon.zzpW.zza(new com.google.android.gms.ads.internal.purchase.zzg(this.zzon.zzpH, str, z, i, intent, zzfVar));
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Fail to invoke PlayStorePurchaseListener.");
        }
        zzhl.zzGk.postDelayed(new Runnable() { // from class: com.google.android.gms.ads.internal.zzb.1
            @Override // java.lang.Runnable
            public void run() {
                int zzd = zzo.zzbF().zzd(intent);
                zzo.zzbF();
                if (zzd == 0 && zzb.this.zzon.zzpO != null && zzb.this.zzon.zzpO.zzzE != null && zzb.this.zzon.zzpO.zzzE.zzgD() != null) {
                    zzb.this.zzon.zzpO.zzzE.zzgD().close();
                }
                zzb.this.zzon.zzqi = false;
            }
        }, 500L);
    }

    protected boolean zza(AdRequestParcel adRequestParcel, zzha zzhaVar, boolean z) {
        if (!z && this.zzon.zzbM()) {
            if (zzhaVar.zzxJ > 0) {
                this.zzom.zza(adRequestParcel, zzhaVar.zzxJ);
            } else if (zzhaVar.zzFm != null && zzhaVar.zzFm.zzxJ > 0) {
                this.zzom.zza(adRequestParcel, zzhaVar.zzFm.zzxJ);
            } else if (!zzhaVar.zzCK && zzhaVar.errorCode == 2) {
                this.zzom.zzf(adRequestParcel);
            }
        }
        return this.zzom.zzbp();
    }

    @Override // com.google.android.gms.ads.internal.zza
    boolean zza(zzha zzhaVar) {
        AdRequestParcel adRequestParcel;
        boolean z = false;
        if (this.zzoo != null) {
            adRequestParcel = this.zzoo;
            this.zzoo = null;
        } else {
            adRequestParcel = zzhaVar.zzCm;
            if (adRequestParcel.extras != null) {
                z = adRequestParcel.extras.getBoolean("_noRefresh", false);
            }
        }
        return zza(adRequestParcel, zzhaVar, z);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.ads.internal.zza
    public boolean zza(zzha zzhaVar, zzha zzhaVar2) {
        int i;
        int i2 = 0;
        if (zzhaVar != null && zzhaVar.zzyc != null) {
            zzhaVar.zzyc.zza((zzdz) null);
        }
        if (zzhaVar2.zzyc != null) {
            zzhaVar2.zzyc.zza(this);
        }
        if (zzhaVar2.zzFm != null) {
            i = zzhaVar2.zzFm.zzxM;
            i2 = zzhaVar2.zzFm.zzxN;
        } else {
            i = 0;
        }
        this.zzon.zzqf.zzf(i, i2);
        return true;
    }

    protected boolean zzaU() {
        return zzo.zzbv().zza(this.zzon.zzpH.getPackageManager(), this.zzon.zzpH.getPackageName(), "android.permission.INTERNET") && zzo.zzbv().zzG(this.zzon.zzpH);
    }

    @Override // com.google.android.gms.ads.internal.overlay.zzf
    public void zzaV() {
        this.zzop.zzg(this.zzon.zzpO);
        this.zzor = false;
        zzaQ();
        this.zzon.zzpQ.zzfR();
    }

    @Override // com.google.android.gms.ads.internal.overlay.zzf
    public void zzaW() {
        this.zzor = true;
        zzaS();
    }

    @Override // com.google.android.gms.internal.zzdz
    public void zzaX() {
        onAdClicked();
    }

    @Override // com.google.android.gms.internal.zzdz
    public void zzaY() {
        zzaV();
    }

    @Override // com.google.android.gms.internal.zzdz
    public void zzaZ() {
        zzaO();
    }

    @Override // com.google.android.gms.ads.internal.zza, com.google.android.gms.internal.zzft.zza
    public void zzb(zzha zzhaVar) {
        super.zzb(zzhaVar);
        if (zzhaVar.errorCode != 3 || zzhaVar.zzFm == null || zzhaVar.zzFm.zzxH == null) {
            return;
        }
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Pinging no fill URLs.");
        zzo.zzbG().zza(this.zzon.zzpH, this.zzon.zzpJ.zzGG, zzhaVar, this.zzon.zzpG, false, zzhaVar.zzFm.zzxH);
    }

    @Override // com.google.android.gms.ads.internal.zza
    public boolean zzb(AdRequestParcel adRequestParcel) {
        if (zzaU()) {
            Bundle zza = zza(zzo.zzby().zzD(this.zzon.zzpH));
            this.zzom.cancel();
            this.zzon.zzqh = 0;
            AdRequestInfoParcel.zza zza2 = zza(adRequestParcel, zza);
            this.zzon.zzpL = zzo.zzbr().zza(this.zzon.zzpH, zza2, this.zzon.zzpI, this);
            return true;
        }
        return false;
    }

    @Override // com.google.android.gms.internal.zzdz
    public void zzba() {
        zzaW();
    }

    @Override // com.google.android.gms.internal.zzdz
    public void zzbb() {
        if (this.zzon.zzpO != null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Mediation adapter " + this.zzon.zzpO.zzyb + " refreshed, but mediation adapters should never refresh.");
        }
        zza(this.zzon.zzpO, true);
        zzaT();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.ads.internal.zza
    public boolean zzc(AdRequestParcel adRequestParcel) {
        return super.zzc(adRequestParcel) && !this.zzor;
    }
}
