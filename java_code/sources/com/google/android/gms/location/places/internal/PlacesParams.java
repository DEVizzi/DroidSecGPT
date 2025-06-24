package com.google.android.gms.location.places.internal;

import android.os.Parcel;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import java.util.Locale;
/* loaded from: classes.dex */
public class PlacesParams implements SafeParcelable {
    public final int versionCode;
    public final String zzaAZ;
    public final String zzaBa;
    public final String zzaBb;
    public final String zzaBc;
    public final int zzaBd;
    public final String zzazX;
    public static final PlacesParams zzaAY = new PlacesParams("com.google.android.gms", Locale.getDefault(), null);
    public static final zzs CREATOR = new zzs();

    public PlacesParams(int versionCode, String clientPackageName, String localeString, String accountName, String gCoreClientName, String chargedPackageName, int gCoreClientJarVersion) {
        this.versionCode = versionCode;
        this.zzaAZ = clientPackageName;
        this.zzaBa = localeString;
        this.zzaBb = accountName;
        this.zzazX = gCoreClientName;
        this.zzaBc = chargedPackageName;
        this.zzaBd = gCoreClientJarVersion;
    }

    public PlacesParams(String clientPackageName, Locale locale, String accountName) {
        this(1, clientPackageName, locale.toString(), accountName, null, null, GoogleApiAvailability.GOOGLE_PLAY_SERVICES_VERSION_CODE);
    }

    public PlacesParams(String clientPackageName, Locale locale, String accountName, String gCoreClientName, String chargedPackageName) {
        this(1, clientPackageName, locale.toString(), accountName, gCoreClientName, chargedPackageName, GoogleApiAvailability.GOOGLE_PLAY_SERVICES_VERSION_CODE);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zzs zzsVar = CREATOR;
        return 0;
    }

    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || !(object instanceof PlacesParams)) {
            return false;
        }
        PlacesParams placesParams = (PlacesParams) object;
        return this.zzaBa.equals(placesParams.zzaBa) && this.zzaAZ.equals(placesParams.zzaAZ) && com.google.android.gms.common.internal.zzt.equal(this.zzaBb, placesParams.zzaBb) && com.google.android.gms.common.internal.zzt.equal(this.zzazX, placesParams.zzazX) && com.google.android.gms.common.internal.zzt.equal(this.zzaBc, placesParams.zzaBc);
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(this.zzaAZ, this.zzaBa, this.zzaBb, this.zzazX, this.zzaBc);
    }

    public String toString() {
        return com.google.android.gms.common.internal.zzt.zzt(this).zzg("clientPackageName", this.zzaAZ).zzg("locale", this.zzaBa).zzg("accountName", this.zzaBb).zzg("gCoreClientName", this.zzazX).zzg("chargedPackageName", this.zzaBc).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzs zzsVar = CREATOR;
        zzs.zza(this, out, flags);
    }
}
