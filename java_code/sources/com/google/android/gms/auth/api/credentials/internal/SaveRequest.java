package com.google.android.gms.auth.api.credentials.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.auth.api.credentials.Credential;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public final class SaveRequest implements SafeParcelable {
    public static final Parcelable.Creator<SaveRequest> CREATOR = new zzf();
    final int zzCY;
    private final Credential zzPb;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SaveRequest(int version, Credential credential) {
        this.zzCY = version;
        this.zzPb = credential;
    }

    public SaveRequest(Credential credential) {
        this(1, credential);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public Credential getCredential() {
        return this.zzPb;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzf.zza(this, out, flags);
    }
}
