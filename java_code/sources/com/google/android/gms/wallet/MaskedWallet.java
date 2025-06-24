package com.google.android.gms.wallet;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.identity.intents.model.UserAddress;
/* loaded from: classes.dex */
public final class MaskedWallet implements SafeParcelable {
    public static final Parcelable.Creator<MaskedWallet> CREATOR = new zzk();
    private final int zzCY;
    String zzaQm;
    String zzaQn;
    String zzaQp;
    Address zzaQq;
    Address zzaQr;
    String[] zzaQs;
    UserAddress zzaQt;
    UserAddress zzaQu;
    InstrumentInfo[] zzaQv;
    LoyaltyWalletObject[] zzaRf;
    OfferWalletObject[] zzaRg;

    /* loaded from: classes.dex */
    public final class Builder {
        private Builder() {
        }

        public MaskedWallet build() {
            return MaskedWallet.this;
        }

        public Builder setBillingAddress(Address billingAddress) {
            MaskedWallet.this.zzaQq = billingAddress;
            return this;
        }

        public Builder setBuyerBillingAddress(UserAddress buyerBillingAddress) {
            MaskedWallet.this.zzaQt = buyerBillingAddress;
            return this;
        }

        public Builder setBuyerShippingAddress(UserAddress buyerShippingAddress) {
            MaskedWallet.this.zzaQu = buyerShippingAddress;
            return this;
        }

        public Builder setEmail(String email) {
            MaskedWallet.this.zzaQp = email;
            return this;
        }

        public Builder setGoogleTransactionId(String googleTransactionId) {
            MaskedWallet.this.zzaQm = googleTransactionId;
            return this;
        }

        public Builder setInstrumentInfos(InstrumentInfo[] instrumentInfos) {
            MaskedWallet.this.zzaQv = instrumentInfos;
            return this;
        }

        public Builder setLoyaltyWalletObjects(LoyaltyWalletObject[] loyaltyWalletObjects) {
            MaskedWallet.this.zzaRf = loyaltyWalletObjects;
            return this;
        }

        public Builder setMerchantTransactionId(String merchantTransactionId) {
            MaskedWallet.this.zzaQn = merchantTransactionId;
            return this;
        }

        public Builder setOfferWalletObjects(OfferWalletObject[] offerWalletObjects) {
            MaskedWallet.this.zzaRg = offerWalletObjects;
            return this;
        }

        public Builder setPaymentDescriptions(String[] paymentDescriptions) {
            MaskedWallet.this.zzaQs = paymentDescriptions;
            return this;
        }

        public Builder setShippingAddress(Address shippingAddress) {
            MaskedWallet.this.zzaQr = shippingAddress;
            return this;
        }
    }

    private MaskedWallet() {
        this.zzCY = 2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MaskedWallet(int versionCode, String googleTransactionId, String merchantTransactionId, String[] paymentDescriptions, String email, Address billingAddress, Address shippingAddress, LoyaltyWalletObject[] loyaltyWalletObjects, OfferWalletObject[] offerWalletObjects, UserAddress buyerBillingAddress, UserAddress buyerShippingAddress, InstrumentInfo[] instrumentInfos) {
        this.zzCY = versionCode;
        this.zzaQm = googleTransactionId;
        this.zzaQn = merchantTransactionId;
        this.zzaQs = paymentDescriptions;
        this.zzaQp = email;
        this.zzaQq = billingAddress;
        this.zzaQr = shippingAddress;
        this.zzaRf = loyaltyWalletObjects;
        this.zzaRg = offerWalletObjects;
        this.zzaQt = buyerBillingAddress;
        this.zzaQu = buyerShippingAddress;
        this.zzaQv = instrumentInfos;
    }

    public static Builder newBuilderFrom(MaskedWallet maskedWallet) {
        zzu.zzu(maskedWallet);
        return zzAJ().setGoogleTransactionId(maskedWallet.getGoogleTransactionId()).setMerchantTransactionId(maskedWallet.getMerchantTransactionId()).setPaymentDescriptions(maskedWallet.getPaymentDescriptions()).setInstrumentInfos(maskedWallet.getInstrumentInfos()).setEmail(maskedWallet.getEmail()).setLoyaltyWalletObjects(maskedWallet.getLoyaltyWalletObjects()).setOfferWalletObjects(maskedWallet.getOfferWalletObjects()).setBuyerBillingAddress(maskedWallet.getBuyerBillingAddress()).setBuyerShippingAddress(maskedWallet.getBuyerShippingAddress());
    }

    public static Builder zzAJ() {
        MaskedWallet maskedWallet = new MaskedWallet();
        maskedWallet.getClass();
        return new Builder();
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

    public LoyaltyWalletObject[] getLoyaltyWalletObjects() {
        return this.zzaRf;
    }

    public String getMerchantTransactionId() {
        return this.zzaQn;
    }

    public OfferWalletObject[] getOfferWalletObjects() {
        return this.zzaRg;
    }

    public String[] getPaymentDescriptions() {
        return this.zzaQs;
    }

    @Deprecated
    public Address getShippingAddress() {
        return this.zzaQr;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzk.zza(this, dest, flags);
    }
}
