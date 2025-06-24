package com.google.android.gms.wallet;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public final class CreateWalletObjectsRequest implements SafeParcelable {
    public static final Parcelable.Creator<CreateWalletObjectsRequest> CREATOR = new zzd();
    private final int zzCY;
    LoyaltyWalletObject zzaQj;
    OfferWalletObject zzaQk;
    GiftCardWalletObject zzaQl;

    CreateWalletObjectsRequest() {
        this.zzCY = 3;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CreateWalletObjectsRequest(int versionCode, LoyaltyWalletObject loyaltyWalletObject, OfferWalletObject offerWalletObject, GiftCardWalletObject giftCardWalletObject) {
        this.zzCY = versionCode;
        this.zzaQj = loyaltyWalletObject;
        this.zzaQk = offerWalletObject;
        this.zzaQl = giftCardWalletObject;
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
        zzd.zza(this, dest, flags);
    }
}
