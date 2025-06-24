package com.google.android.gms.wallet.wobs;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public final class TextModuleData implements SafeParcelable {
    public static final Parcelable.Creator<TextModuleData> CREATOR = new zzf();
    String zzCI;
    private final int zzCY;
    String zzaSG;

    TextModuleData() {
        this.zzCY = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public TextModuleData(int versionCode, String header, String body) {
        this.zzCY = versionCode;
        this.zzaSG = header;
        this.zzCI = body;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzf.zza(this, dest, flags);
    }
}
