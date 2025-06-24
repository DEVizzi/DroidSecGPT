package com.google.android.gms.ads.internal;

import android.app.Activity;
import android.content.Context;
import android.text.TextUtils;
import com.google.android.gms.ads.AdActivity;
import com.google.android.gms.ads.internal.client.MobileAdsSettingsParcel;
import com.google.android.gms.ads.internal.client.zzv;
import com.google.android.gms.ads.purchase.InAppPurchaseActivity;
import com.google.android.gms.analytics.GoogleAnalytics;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zznw;
import com.google.android.gms.internal.zzod;
import com.google.android.gms.internal.zzpv;
import com.google.android.gms.internal.zzpw;
import java.util.regex.Pattern;
@zzgd
/* loaded from: classes.dex */
public class zzl extends zzv.zza implements zznw.zza, zzpw.zza {
    private static final Object zzoW = new Object();
    private static zzl zzoX;
    private final Context mContext;
    zzpv zzoY;
    String zzoZ;
    String zzpa;
    private boolean zzpb = false;
    private boolean zzpc;

    zzl(Context context) {
        this.mContext = context;
    }

    public static zzl zzq(Context context) {
        zzl zzlVar;
        synchronized (zzoW) {
            if (zzoX == null) {
                zzoX = new zzl(context.getApplicationContext());
            }
            zzlVar = zzoX;
        }
        return zzlVar;
    }

    public String getClientId() {
        String clientId;
        synchronized (zzoW) {
            clientId = !this.zzpc ? null : GoogleAnalytics.getInstance(this.mContext).getClientId();
        }
        return clientId;
    }

    @Override // com.google.android.gms.internal.zznw.zza
    public void zza(zzod zzodVar) {
    }

    @Override // com.google.android.gms.internal.zznw.zza
    public void zza(zzod zzodVar, Activity activity) {
        if (zzodVar == null || activity == null) {
            return;
        }
        if (!(activity instanceof AdActivity)) {
            if (activity instanceof InAppPurchaseActivity) {
                zzodVar.setScreenName(null);
                return;
            }
            return;
        }
        int zzk = zzo.zzbv().zzk(activity);
        if (zzk == 1) {
            zzodVar.zzai(true);
            zzodVar.setScreenName("Interstitial Ad");
        } else if (zzk == 2 || zzk == 3) {
            zzodVar.setScreenName("Expanded Ad");
        } else {
            zzodVar.setScreenName(null);
        }
    }

    @Override // com.google.android.gms.ads.internal.client.zzv
    public void zza(String str, MobileAdsSettingsParcel mobileAdsSettingsParcel) {
        synchronized (zzoW) {
            if (this.zzpb) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Mobile ads is initialized already.");
            } else if (this.mContext == null) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Fail to initialize mobile ads because context is null.");
            } else if (TextUtils.isEmpty(str)) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Fail to initialize mobile ads because ApplicationCode is empty.");
            } else {
                this.zzpb = true;
                zzb(str, mobileAdsSettingsParcel);
            }
        }
    }

    void zzb(String str, MobileAdsSettingsParcel mobileAdsSettingsParcel) {
        if (mobileAdsSettingsParcel == null || !mobileAdsSettingsParcel.zztf) {
            return;
        }
        if (!zzo.zzbv().zza(this.mContext.getPackageManager(), this.mContext.getPackageName(), "android.permission.INTERNET")) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaz("Missing permission android.permission.INTERNET");
        } else if (!zzo.zzbv().zza(this.mContext.getPackageManager(), this.mContext.getPackageName(), "android.permission.ACCESS_NETWORK_STATE")) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaz("Missing permission android.permission.ACCESS_NETWORK_STATE");
        } else if (!Pattern.matches("ca-app-[a-z0-9_-]+~[a-z0-9_-]+", str)) {
            throw new IllegalArgumentException("Please provide a valid application code");
        } else {
            this.zzpc = true;
            this.zzoZ = str;
            this.zzpa = mobileAdsSettingsParcel.zztg;
            zzpw zzaK = zzpw.zzaK(this.mContext);
            zzpv.zza zzaVar = new zzpv.zza(this.zzoZ);
            if (!TextUtils.isEmpty(this.zzpa)) {
                zzaVar.zzeS(this.zzpa);
            }
            zzaK.zza(zzaVar.zzzW());
            zzaK.zza(this);
            zznw.zzaC(this.mContext).zza(this);
            zzaK.start();
        }
    }

    public boolean zzbl() {
        boolean z;
        synchronized (zzoW) {
            z = this.zzpc;
        }
        return z;
    }

    @Override // com.google.android.gms.internal.zzpw.zza
    public void zzbm() {
        this.zzoY = zzpw.zzaK(this.mContext).zzzX();
    }

    public int zzbn() {
        int i = -1;
        synchronized (zzoW) {
            if (this.zzpc) {
                zzod zzwe = zznw.zzaC(this.mContext).zzwe();
                if (zzwe != null) {
                    i = zzwe.zzbn();
                }
            }
        }
        return i;
    }
}
