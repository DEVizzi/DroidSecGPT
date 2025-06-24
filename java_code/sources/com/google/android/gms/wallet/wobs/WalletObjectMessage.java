package com.google.android.gms.wallet.wobs;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public final class WalletObjectMessage implements SafeParcelable {
    public static final Parcelable.Creator<WalletObjectMessage> CREATOR = new zzi();
    String zzCI;
    private final int zzCY;
    String zzaSG;
    TimeInterval zzaSJ;
    UriData zzaSK;
    UriData zzaSL;

    WalletObjectMessage() {
        this.zzCY = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public WalletObjectMessage(int versionCode, String header, String body, TimeInterval displayInterval, UriData actionUri, UriData imageUri) {
        this.zzCY = versionCode;
        this.zzaSG = header;
        this.zzCI = body;
        this.zzaSJ = displayInterval;
        this.zzaSK = actionUri;
        this.zzaSL = imageUri;
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
        zzi.zza(this, dest, flags);
    }
}
