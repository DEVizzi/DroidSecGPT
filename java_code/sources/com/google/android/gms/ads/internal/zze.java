package com.google.android.gms.ads.internal;

import android.content.Context;
import android.os.RemoteException;
import android.view.View;
import com.google.android.gms.ads.internal.client.AdSizeParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.zzaz;
import com.google.android.gms.internal.zzef;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzha;
import com.google.android.gms.internal.zzid;
@zzgd
/* loaded from: classes.dex */
public class zze extends zzc {
    public zze(Context context, AdSizeParcel adSizeParcel, String str, zzef zzefVar, VersionInfoParcel versionInfoParcel) {
        super(context, adSizeParcel, str, zzefVar, versionInfoParcel);
    }

    private boolean zzb(zzha zzhaVar, zzha zzhaVar2) {
        boolean z;
        if (zzhaVar2.zzCK) {
            try {
                com.google.android.gms.dynamic.zzd view = zzhaVar2.zzya.getView();
                if (view == null) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzaC("View in mediation adapter is null.");
                    z = false;
                } else {
                    View view2 = (View) com.google.android.gms.dynamic.zze.zzn(view);
                    View nextView = this.zzon.zzpK.getNextView();
                    if (nextView != null) {
                        if (nextView instanceof zzid) {
                            ((zzid) nextView).destroy();
                        }
                        this.zzon.zzpK.removeView(nextView);
                    }
                    try {
                        zzb(view2);
                    } catch (Throwable th) {
                        com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not add mediation view to view hierarchy.", th);
                        z = false;
                    }
                }
                return z;
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not get View from mediation adapter.", e);
                return false;
            }
        } else if (zzhaVar2.zzFn != null) {
            zzhaVar2.zzzE.zza(zzhaVar2.zzFn);
            this.zzon.zzpK.removeAllViews();
            this.zzon.zzpK.setMinimumWidth(zzhaVar2.zzFn.widthPixels);
            this.zzon.zzpK.setMinimumHeight(zzhaVar2.zzFn.heightPixels);
            zzb(zzhaVar2.zzzE.getWebView());
        }
        if (this.zzon.zzpK.getChildCount() > 1) {
            this.zzon.zzpK.showNext();
        }
        if (zzhaVar != null) {
            View nextView2 = this.zzon.zzpK.getNextView();
            if (nextView2 instanceof zzid) {
                ((zzid) nextView2).zza(this.zzon.zzpH, this.zzon.zzpN);
            } else if (nextView2 != null) {
                this.zzon.zzpK.removeView(nextView2);
            }
            this.zzon.zzbL();
        }
        this.zzon.zzpK.setVisibility(0);
        z = true;
        return z;
    }

    @Override // com.google.android.gms.ads.internal.zzb, com.google.android.gms.ads.internal.client.zzr
    public void showInterstitial() {
        throw new IllegalStateException("Interstitial is NOT supported by BannerAdManager.");
    }

    @Override // com.google.android.gms.ads.internal.zzc, com.google.android.gms.ads.internal.zzb, com.google.android.gms.ads.internal.zza
    public boolean zza(zzha zzhaVar, zzha zzhaVar2) {
        if (super.zza(zzhaVar, zzhaVar2)) {
            if (this.zzon.zzbM() && !zzb(zzhaVar, zzhaVar2)) {
                zze(0);
                return false;
            }
            zza(zzhaVar2, false);
            if (this.zzon.zzbM()) {
                if (zzhaVar2.zzzE != null && (zzhaVar2.zzzE.zzgF().zzbU() || zzhaVar2.zzFl != null)) {
                    zzaz zza = this.zzop.zza(this.zzon.zzpN, zzhaVar2);
                    if (zzhaVar2.zzzE.zzgF().zzbU() && zza != null) {
                        zza.zza(this);
                    }
                }
                if (zzhaVar2.zzzE != null) {
                    zzhaVar2.zzzE.zzgF().zzgS();
                }
            } else if (this.zzon.zzqg != null && zzhaVar2.zzFl != null) {
                this.zzop.zza(this.zzon.zzpN, zzhaVar2, this.zzon.zzqg);
            }
            return true;
        }
        return false;
    }

    @Override // com.google.android.gms.ads.internal.zzb
    protected boolean zzaU() {
        boolean z = true;
        if (!zzo.zzbv().zza(this.zzon.zzpH.getPackageManager(), this.zzon.zzpH.getPackageName(), "android.permission.INTERNET")) {
            com.google.android.gms.ads.internal.client.zzk.zzcA().zza(this.zzon.zzpK, this.zzon.zzpN, "Missing internet permission in AndroidManifest.xml.", "Missing internet permission in AndroidManifest.xml. You must have the following declaration: <uses-permission android:name=\"android.permission.INTERNET\" />");
            z = false;
        }
        if (!zzo.zzbv().zzG(this.zzon.zzpH)) {
            com.google.android.gms.ads.internal.client.zzk.zzcA().zza(this.zzon.zzpK, this.zzon.zzpN, "Missing AdActivity with android:configChanges in AndroidManifest.xml.", "Missing AdActivity with android:configChanges in AndroidManifest.xml. You must have the following declaration within the <application> element: <activity android:name=\"com.google.android.gms.ads.AdActivity\" android:configChanges=\"keyboard|keyboardHidden|orientation|screenLayout|uiMode|screenSize|smallestScreenSize\" />");
            z = false;
        }
        if (!z && this.zzon.zzpK != null) {
            this.zzon.zzpK.setVisibility(0);
        }
        return z;
    }
}
