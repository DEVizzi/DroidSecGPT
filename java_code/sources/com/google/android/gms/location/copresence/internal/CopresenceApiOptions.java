package com.google.android.gms.location.copresence.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public final class CopresenceApiOptions implements SafeParcelable {
    public static final Parcelable.Creator<CopresenceApiOptions> CREATOR = new zza();
    public static final CopresenceApiOptions zzayn = new CopresenceApiOptions(true, null);
    final int zzCY;
    public final boolean zzayo;
    public final String zzayp;

    /* JADX INFO: Access modifiers changed from: package-private */
    public CopresenceApiOptions(int versionCode, boolean isAuthenticated, String zeroPartyPackageName) {
        this.zzCY = versionCode;
        this.zzayo = isAuthenticated;
        this.zzayp = zeroPartyPackageName;
    }

    public CopresenceApiOptions(boolean isAuthenticated, String zeroPartyPackageName) {
        this(1, isAuthenticated, zeroPartyPackageName);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zza.zza(this, dest, flags);
    }
}
