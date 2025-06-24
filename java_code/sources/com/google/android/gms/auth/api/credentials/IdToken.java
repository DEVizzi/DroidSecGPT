package com.google.android.gms.auth.api.credentials;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public final class IdToken implements SafeParcelable {
    public static final Parcelable.Creator<IdToken> CREATOR = new zzc();
    final int zzCY;
    private final String zzOX;
    private final String zzPa;

    /* JADX INFO: Access modifiers changed from: package-private */
    public IdToken(int version, String accountType, String idToken) {
        this.zzCY = version;
        this.zzOX = accountType;
        this.zzPa = idToken;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String getAccountType() {
        return this.zzOX;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzc.zza(this, out, flags);
    }

    public String zzlc() {
        return this.zzPa;
    }
}
