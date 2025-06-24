package com.google.android.gms.wallet;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.identity.intents.model.UserAddress;
/* loaded from: classes.dex */
public final class FullWallet implements SafeParcelable {
    public static final Parcelable.Creator<FullWallet> CREATOR = new zze();
    private final int zzCY;
    String zzaQm;
    String zzaQn;
    ProxyCard zzaQo;
    String zzaQp;
    Address zzaQq;
    Address zzaQr;
    String[] zzaQs;
    UserAddress zzaQt;
    UserAddress zzaQu;
    InstrumentInfo[] zzaQv;
    PaymentMethodToken zzaQw;

    private FullWallet() {
        this.zzCY = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public FullWallet(int versionCode, String googleTransactionId, String merchantTransactionId, ProxyCard proxyCard, String email, Address billingAddress, Address shippingAddress, String[] paymentDescriptions, UserAddress buyerBillingAddress, UserAddress buyerShippingAddress, InstrumentInfo[] instrumentInfos, PaymentMethodToken paymentMethodToken) {
        this.zzCY = versionCode;
        this.zzaQm = googleTransactionId;
        this.zzaQn = merchantTransactionId;
        this.zzaQo = proxyCard;
        this.zzaQp = email;
        this.zzaQq = billingAddress;
        this.zzaQr = shippingAddress;
        this.zzaQs = paymentDescriptions;
        this.zzaQt = buyerBillingAddress;
        this.zzaQu = buyerShippingAddress;
        this.zzaQv = instrumentInfos;
        this.zzaQw = paymentMethodToken;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Deprecated
    public Address getBillingAddress() {
        return this.zzaQq;
    }

    public UserAddress getBuyerBillingAddress() {
        return this.zzaQt;
    }

    public UserAddress getBuyerShippingAddress() {
        return this.zzaQu;
    }

    public String getEmail() {
        return this.zzaQp;
    }

    public String getGoogleTransactionId() {
        return this.zzaQm;
    }

    public InstrumentInfo[] getInstrumentInfos() {
        return this.zzaQv;
    }

    public String getMerchantTransactionId() {
        return this.zzaQn;
    }

    public String[] getPaymentDescriptions() {
        return this.zzaQs;
    }

    public PaymentMethodToken getPaymentMethodToken() {
        return this.zzaQw;
    }

    public ProxyCard getProxyCard() {
        return this.zzaQo;
    }

    @Deprecated
    public Address getShippingAddress() {
        return this.zzaQr;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zze.zza(this, out, flags);
    }
}
