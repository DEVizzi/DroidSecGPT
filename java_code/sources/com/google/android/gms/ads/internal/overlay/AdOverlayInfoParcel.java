package com.google.android.gms.ads.internal.overlay;

import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.ads.internal.InterstitialAdParameterParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.dynamic.zzd;
import com.google.android.gms.internal.zzde;
import com.google.android.gms.internal.zzdi;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzid;
@zzgd
/* loaded from: classes.dex */
public final class AdOverlayInfoParcel implements SafeParcelable {
    public static final zze CREATOR = new zze();
    public final int orientation;
    public final int versionCode;
    public final VersionInfoParcel zzpJ;
    public final AdLauncherIntentInfoParcel zzzB;
    public final com.google.android.gms.ads.internal.client.zza zzzC;
    public final zzf zzzD;
    public final zzid zzzE;
    public final zzde zzzF;
    public final String zzzG;
    public final boolean zzzH;
    public final String zzzI;
    public final zzk zzzJ;
    public final int zzzK;
    public final zzdi zzzL;
    public final String zzzM;
    public final InterstitialAdParameterParcel zzzN;
    public final String zzzf;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AdOverlayInfoParcel(int versionCode, AdLauncherIntentInfoParcel adLauncherIntentInfo, IBinder wrappedAdClickListener, IBinder wrappedAdOverlayListener, IBinder wrappedAdWebView, IBinder wrappedAppEventGmsgListener, String baseUrl, boolean customClose, String html, IBinder wrappedLeaveApplicationListener, int orientation, int overlayType, String url, VersionInfoParcel versionInfo, IBinder wrappedInAppPurchaseGmsgListener, String debugMessage, InterstitialAdParameterParcel interstitialAdParameter) {
        this.versionCode = versionCode;
        this.zzzB = adLauncherIntentInfo;
        this.zzzC = (com.google.android.gms.ads.internal.client.zza) com.google.android.gms.dynamic.zze.zzn(zzd.zza.zzbg(wrappedAdClickListener));
        this.zzzD = (zzf) com.google.android.gms.dynamic.zze.zzn(zzd.zza.zzbg(wrappedAdOverlayListener));
        this.zzzE = (zzid) com.google.android.gms.dynamic.zze.zzn(zzd.zza.zzbg(wrappedAdWebView));
        this.zzzF = (zzde) com.google.android.gms.dynamic.zze.zzn(zzd.zza.zzbg(wrappedAppEventGmsgListener));
        this.zzzG = baseUrl;
        this.zzzH = customClose;
        this.zzzI = html;
        this.zzzJ = (zzk) com.google.android.gms.dynamic.zze.zzn(zzd.zza.zzbg(wrappedLeaveApplicationListener));
        this.orientation = orientation;
        this.zzzK = overlayType;
        this.zzzf = url;
        this.zzpJ = versionInfo;
        this.zzzL = (zzdi) com.google.android.gms.dynamic.zze.zzn(zzd.zza.zzbg(wrappedInAppPurchaseGmsgListener));
        this.zzzM = debugMessage;
        this.zzzN = interstitialAdParameter;
    }

    public AdOverlayInfoParcel(com.google.android.gms.ads.internal.client.zza adClickListener, zzf adOverlayListener, zzk leaveApplicationListener, zzid adWebView, int orientation, VersionInfoParcel versionInfo, String debugMessage, InterstitialAdParameterParcel interstitialAdParameter) {
        this.versionCode = 4;
        this.zzzB = null;
        this.zzzC = adClickListener;
        this.zzzD = adOverlayListener;
        this.zzzE = adWebView;
        this.zzzF = null;
        this.zzzG = null;
        this.zzzH = false;
        this.zzzI = null;
        this.zzzJ = leaveApplicationListener;
        this.orientation = orientation;
        this.zzzK = 1;
        this.zzzf = null;
        this.zzpJ = versionInfo;
        this.zzzL = null;
        this.zzzM = debugMessage;
        this.zzzN = interstitialAdParameter;
    }

    public AdOverlayInfoParcel(com.google.android.gms.ads.internal.client.zza adClickListener, zzf adOverlayListener, zzk leaveApplicationListener, zzid adWebView, boolean customClose, int orientation, VersionInfoParcel versionInfo) {
        this.versionCode = 4;
        this.zzzB = null;
        this.zzzC = adClickListener;
        this.zzzD = adOverlayListener;
        this.zzzE = adWebView;
        this.zzzF = null;
        this.zzzG = null;
        this.zzzH = customClose;
        this.zzzI = null;
        this.zzzJ = leaveApplicationListener;
        this.orientation = orientation;
        this.zzzK = 2;
        this.zzzf = null;
        this.zzpJ = versionInfo;
        this.zzzL = null;
        this.zzzM = null;
        this.zzzN = null;
    }

    public AdOverlayInfoParcel(com.google.android.gms.ads.internal.client.zza adClickListener, zzf adOverlayListener, zzde appEventGmsgListener, zzk leaveApplicationListener, zzid adWebView, boolean customClose, int orientation, String url, VersionInfoParcel versionInfo, zzdi inAppPurchaseGmsgListener) {
        this.versionCode = 4;
        this.zzzB = null;
        this.zzzC = adClickListener;
        this.zzzD = adOverlayListener;
        this.zzzE = adWebView;
        this.zzzF = appEventGmsgListener;
        this.zzzG = null;
        this.zzzH = customClose;
        this.zzzI = null;
        this.zzzJ = leaveApplicationListener;
        this.orientation = orientation;
        this.zzzK = 3;
        this.zzzf = url;
        this.zzpJ = versionInfo;
        this.zzzL = inAppPurchaseGmsgListener;
        this.zzzM = null;
        this.zzzN = null;
    }

    public AdOverlayInfoParcel(com.google.android.gms.ads.internal.client.zza adClickListener, zzf adOverlayListener, zzde appEventGmsgListener, zzk leaveApplicationListener, zzid adWebView, boolean customClose, int orientation, String html, String baseUrl, VersionInfoParcel versionInfo, zzdi inAppPurchaseGmsgListener) {
        this.versionCode = 4;
        this.zzzB = null;
        this.zzzC = adClickListener;
        this.zzzD = adOverlayListener;
        this.zzzE = adWebView;
        this.zzzF = appEventGmsgListener;
        this.zzzG = baseUrl;
        this.zzzH = customClose;
        this.zzzI = html;
        this.zzzJ = leaveApplicationListener;
        this.orientation = orientation;
        this.zzzK = 3;
        this.zzzf = null;
        this.zzpJ = versionInfo;
        this.zzzL = inAppPurchaseGmsgListener;
        this.zzzM = null;
        this.zzzN = null;
    }

    public AdOverlayInfoParcel(AdLauncherIntentInfoParcel adLauncherIntentInfo, com.google.android.gms.ads.internal.client.zza adClickListener, zzf adOverlayListener, zzk leaveApplicationListener, VersionInfoParcel versionInfo) {
        this.versionCode = 4;
        this.zzzB = adLauncherIntentInfo;
        this.zzzC = adClickListener;
        this.zzzD = adOverlayListener;
        this.zzzE = null;
        this.zzzF = null;
        this.zzzG = null;
        this.zzzH = false;
        this.zzzI = null;
        this.zzzJ = leaveApplicationListener;
        this.orientation = -1;
        this.zzzK = 4;
        this.zzzf = null;
        this.zzpJ = versionInfo;
        this.zzzL = null;
        this.zzzM = null;
        this.zzzN = null;
    }

    public static void zza(Intent intent, AdOverlayInfoParcel adOverlayInfoParcel) {
        Bundle bundle = new Bundle(1);
        bundle.putParcelable("com.google.android.gms.ads.inernal.overlay.AdOverlayInfo", adOverlayInfoParcel);
        intent.putExtra("com.google.android.gms.ads.inernal.overlay.AdOverlayInfo", bundle);
    }

    public static AdOverlayInfoParcel zzb(Intent intent) {
        try {
            Bundle bundleExtra = intent.getBundleExtra("com.google.android.gms.ads.inernal.overlay.AdOverlayInfo");
            bundleExtra.setClassLoader(AdOverlayInfoParcel.class.getClassLoader());
            return (AdOverlayInfoParcel) bundleExtra.getParcelable("com.google.android.gms.ads.inernal.overlay.AdOverlayInfo");
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
        zze.zza(this, out, flags);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzeA() {
        return com.google.android.gms.dynamic.zze.zzw(this.zzzF).asBinder();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzeB() {
        return com.google.android.gms.dynamic.zze.zzw(this.zzzL).asBinder();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzeC() {
        return com.google.android.gms.dynamic.zze.zzw(this.zzzJ).asBinder();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzex() {
        return com.google.android.gms.dynamic.zze.zzw(this.zzzC).asBinder();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzey() {
        return com.google.android.gms.dynamic.zze.zzw(this.zzzD).asBinder();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzez() {
        return com.google.android.gms.dynamic.zze.zzw(this.zzzE).asBinder();
    }
}
