package com.google.android.gms.wallet.firstparty;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public final class GetInstrumentsRequest implements SafeParcelable {
    public static final Parcelable.Creator<GetInstrumentsRequest> CREATOR = new zzd();
    private final int zzCY;
    int[] zzaRL;

    GetInstrumentsRequest() {
        this(1, null);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public GetInstrumentsRequest(int versionCode, int[] familyFilter) {
        this.zzCY = versionCode;
        this.zzaRL = familyFilter;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzd.zza(this, out, flags);
    }
}
