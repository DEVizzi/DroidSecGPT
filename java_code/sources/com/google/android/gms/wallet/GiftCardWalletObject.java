package com.google.android.gms.wallet;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.wallet.wobs.CommonWalletObject;
/* loaded from: classes.dex */
public final class GiftCardWalletObject implements SafeParcelable {
    public static final Parcelable.Creator<GiftCardWalletObject> CREATOR = new zzg();
    String pin;
    final int zzCY;
    String zzaQA;
    String zzaQB;
    long zzaQC;
    String zzaQD;
    long zzaQE;
    String zzaQF;
    CommonWalletObject zzaQz;

    GiftCardWalletObject() {
        this.zzaQz = CommonWalletObject.zzAN().zzAO();
        this.zzCY = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public GiftCardWalletObject(int versionCode, CommonWalletObject commonWalletObject, String cardNumber, String pin, String cardIdentifier, long balanceMicros, String balanceCurrencyCode, long balanceUpdateTime, String eventNumber) {
        this.zzaQz = CommonWalletObject.zzAN().zzAO();
        this.zzCY = versionCode;
        this.zzaQz = commonWalletObject;
        this.zzaQA = cardNumber;
        this.pin = pin;
        this.zzaQC = balanceMicros;
        this.zzaQD = balanceCurrencyCode;
        this.zzaQE = balanceUpdateTime;
        this.zzaQF = eventNumber;
        this.zzaQB = cardIdentifier;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String getId() {
        return this.zzaQz.getId();
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzg.zza(this, dest, flags);
    }
}
