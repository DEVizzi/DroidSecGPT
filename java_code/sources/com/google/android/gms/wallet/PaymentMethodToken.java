package com.google.android.gms.wallet;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public final class PaymentMethodToken implements SafeParcelable {
    public static final Parcelable.Creator<PaymentMethodToken> CREATOR = new zzo();
    private final int zzCY;
    String zzaFl;
    int zzaRz;

    private PaymentMethodToken() {
        this.zzCY = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public PaymentMethodToken(int versionCode, int tokenizationType, String token) {
        this.zzCY = versionCode;
        this.zzaRz = tokenizationType;
        this.zzaFl = token;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public int getPaymentMethodTokenizationType() {
        return this.zzaRz;
    }

    public String getToken() {
        return this.zzaFl;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzo.zza(this, out, flags);
    }
}
