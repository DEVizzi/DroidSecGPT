package com.google.android.gms.safetynet;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class AttestationData implements SafeParcelable {
    public static final Parcelable.Creator<AttestationData> CREATOR = new zza();
    public final int zzCY;
    private String zzaJx;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AttestationData(int versionCode, String attestationToken) {
        this.zzCY = versionCode;
        this.zzaJx = attestationToken;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String getJwsResult() {
        return this.zzaJx;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zza.zza(this, out, flags);
    }
}
