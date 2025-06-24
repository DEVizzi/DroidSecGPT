package com.google.android.gms.ads.internal.purchase;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.dynamic.zzd;
import com.google.android.gms.internal.zzfe;
import com.google.android.gms.internal.zzgd;
@zzgd
/* loaded from: classes.dex */
public final class GInAppPurchaseManagerInfoParcel implements SafeParcelable {
    public static final zza CREATOR = new zza();
    public final int versionCode;
    public final zzj zzAA;
    public final zzfe zzAy;
    public final Context zzAz;
    public final zzk zzqe;

    /* JADX INFO: Access modifiers changed from: package-private */
    public GInAppPurchaseManagerInfoParcel(int versionCode, IBinder wrappedInAppPurchaseVerifier, IBinder wrappedInAppPurchase, IBinder wrappedAppContext, IBinder wrappedOnPlayStorePurchaseFinishedListener) {
        this.versionCode = versionCode;
        this.zzqe = (zzk) com.google.android.gms.dynamic.zze.zzn(zzd.zza.zzbg(wrappedInAppPurchaseVerifier));
        this.zzAy = (zzfe) com.google.android.gms.dynamic.zze.zzn(zzd.zza.zzbg(wrappedInAppPurchase));
        this.zzAz = (Context) com.google.android.gms.dynamic.zze.zzn(zzd.zza.zzbg(wrappedAppContext));
        this.zzAA = (zzj) com.google.android.gms.dynamic.zze.zzn(zzd.zza.zzbg(wrappedOnPlayStorePurchaseFinishedListener));
    }

    public GInAppPurchaseManagerInfoParcel(Context appContext, zzk inAppPurchaseVerifier, zzfe inAppPurchase, zzj onPlayStorePurchaseFinishedListener) {
        this.versionCode = 2;
        this.zzAz = appContext;
        this.zzqe = inAppPurchaseVerifier;
        this.zzAy = inAppPurchase;
        this.zzAA = onPlayStorePurchaseFinishedListener;
    }

    public static void zza(Intent intent, GInAppPurchaseManagerInfoParcel gInAppPurchaseManagerInfoParcel) {
        Bundle bundle = new Bundle(1);
        bundle.putParcelable("com.google.android.gms.ads.internal.purchase.InAppPurchaseManagerInfo", gInAppPurchaseManagerInfoParcel);
        intent.putExtra("com.google.android.gms.ads.internal.purchase.InAppPurchaseManagerInfo", bundle);
    }

    public static GInAppPurchaseManagerInfoParcel zzc(Intent intent) {
        try {
            Bundle bundleExtra = intent.getBundleExtra("com.google.android.gms.ads.internal.purchase.InAppPurchaseManagerInfo");
            bundleExtra.setClassLoader(GInAppPurchaseManagerInfoParcel.class.getClassLoader());
            return (GInAppPurchaseManagerInfoParcel) bundleExtra.getParcelable("com.google.android.gms.ads.internal.purchase.InAppPurchaseManagerInfo");
        } catch (Exception e) {
            return null;
        }
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zza.zza(this, out, flags);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzfa() {
        return com.google.android.gms.dynamic.zze.zzw(this.zzAA).asBinder();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzfb() {
        return com.google.android.gms.dynamic.zze.zzw(this.zzqe).asBinder();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzfc() {
        return com.google.android.gms.dynamic.zze.zzw(this.zzAy).asBinder();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzfd() {
        return com.google.android.gms.dynamic.zze.zzw(this.zzAz).asBinder();
    }
}
