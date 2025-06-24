package com.google.android.gms.ads.internal.overlay;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.internal.zzgd;
@zzgd
/* loaded from: classes.dex */
public final class AdLauncherIntentInfoParcel implements SafeParcelable {
    public static final zzb CREATOR = new zzb();
    public final String mimeType;
    public final String packageName;
    public final int versionCode;
    public final String zzze;
    public final String zzzf;
    public final String zzzg;
    public final String zzzh;
    public final String zzzi;

    public AdLauncherIntentInfoParcel(int versionCode, String intentAction, String url, String mimeType, String packageName, String componentName, String intentFlagsString, String intentExtrasString) {
        this.versionCode = versionCode;
        this.zzze = intentAction;
        this.zzzf = url;
        this.mimeType = mimeType;
        this.packageName = packageName;
        this.zzzg = componentName;
        this.zzzh = intentFlagsString;
        this.zzzi = intentExtrasString;
    }

    public AdLauncherIntentInfoParcel(String intentAction, String url, String mimeType, String packageName, String componentName, String intentFlagsString, String intentExtrasString) {
        this(1, intentAction, url, mimeType, packageName, componentName, intentFlagsString, intentExtrasString);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzb.zza(this, out, flags);
    }
}
