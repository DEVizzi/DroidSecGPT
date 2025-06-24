package com.google.android.gms.wallet;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import java.util.ArrayList;
import java.util.Collection;
/* loaded from: classes.dex */
public final class MaskedWalletRequest implements SafeParcelable {
    public static final Parcelable.Creator<MaskedWalletRequest> CREATOR = new zzl();
    private final int zzCY;
    String zzaQg;
    String zzaQn;
    Cart zzaQx;
    boolean zzaRi;
    boolean zzaRj;
    boolean zzaRk;
    String zzaRl;
    String zzaRm;
    boolean zzaRn;
    boolean zzaRo;
    CountrySpecification[] zzaRp;
    boolean zzaRq;
    boolean zzaRr;
    ArrayList<com.google.android.gms.identity.intents.model.CountrySpecification> zzaRs;
    PaymentMethodTokenizationParameters zzaRt;
    ArrayList<Integer> zzaRu;

    /* loaded from: classes.dex */
    public final class Builder {
        private Builder() {
        }

        public Builder addAllowedCardNetwork(int allowedCardNetwork) {
            if (MaskedWalletRequest.this.zzaRu == null) {
                MaskedWalletRequest.this.zzaRu = new ArrayList<>();
            }
            MaskedWalletRequest.this.zzaRu.add(Integer.valueOf(allowedCardNetwork));
            return this;
        }

        public Builder addAllowedCardNetworks(Collection<Integer> allowedCardNetworks) {
            if (allowedCardNetworks != null) {
                if (MaskedWalletRequest.this.zzaRu == null) {
                    MaskedWalletRequest.this.zzaRu = new ArrayList<>();
                }
                MaskedWalletRequest.this.zzaRu.addAll(allowedCardNetworks);
            }
            return this;
        }

        public Builder addAllowedCountrySpecificationForShipping(com.google.android.gms.identity.intents.model.CountrySpecification countrySpecification) {
            if (MaskedWalletRequest.this.zzaRs == null) {
                MaskedWalletRequest.this.zzaRs = new ArrayList<>();
            }
            MaskedWalletRequest.this.zzaRs.add(countrySpecification);
            return this;
        }

        public Builder addAllowedCountrySpecificationsForShipping(Collection<com.google.android.gms.identity.intents.model.CountrySpecification> countrySpecifications) {
            if (countrySpecifications != null) {
                if (MaskedWalletRequest.this.zzaRs == null) {
                    MaskedWalletRequest.this.zzaRs = new ArrayList<>();
                }
                MaskedWalletRequest.this.zzaRs.addAll(countrySpecifications);
            }
            return this;
        }

        public MaskedWalletRequest build() {
            return MaskedWalletRequest.this;
        }

        public Builder setAllowDebitCard(boolean allowDebitCard) {
            MaskedWalletRequest.this.zzaRr = allowDebitCard;
            return this;
        }

        public Builder setAllowPrepaidCard(boolean allowPrepaidCard) {
            MaskedWalletRequest.this.zzaRq = allowPrepaidCard;
            return this;
        }

        public Builder setCart(Cart cart) {
            MaskedWalletRequest.this.zzaQx = cart;
            return this;
        }

        public Builder setCurrencyCode(String currencyCode) {
            MaskedWalletRequest.this.zzaQg = currencyCode;
            return this;
        }

        public Builder setEstimatedTotalPrice(String estimatedTotalPrice) {
            MaskedWalletRequest.this.zzaRl = estimatedTotalPrice;
            return this;
        }

        public Builder setIsBillingAgreement(boolean isBillingAgreement) {
            MaskedWalletRequest.this.zzaRo = isBillingAgreement;
            return this;
        }

        public Builder setMerchantName(String merchantName) {
            MaskedWalletRequest.this.zzaRm = merchantName;
            return this;
        }

        public Builder setMerchantTransactionId(String merchantTransactionId) {
            MaskedWalletRequest.this.zzaQn = merchantTransactionId;
            return this;
        }

        public Builder setPaymentMethodTokenizationParameters(PaymentMethodTokenizationParameters paymentMethodTokenizationParameters) {
            MaskedWalletRequest.this.zzaRt = paymentMethodTokenizationParameters;
            return this;
        }

        public Builder setPhoneNumberRequired(boolean phoneNumberRequired) {
            MaskedWalletRequest.this.zzaRi = phoneNumberRequired;
            return this;
        }

        public Builder setShippingAddressRequired(boolean shippingAddressRequired) {
            MaskedWalletRequest.this.zzaRj = shippingAddressRequired;
            return this;
        }

        public Builder setShouldRetrieveWalletObjects(boolean shouldRetrieveWalletObjects) {
            MaskedWalletRequest.this.zzaRn = shouldRetrieveWalletObjects;
            return this;
        }

        public Builder setUseMinimalBillingAddress(boolean useMinimalBillingAddress) {
            MaskedWalletRequest.this.zzaRk = useMinimalBillingAddress;
            return this;
        }
    }

    MaskedWalletRequest() {
        this.zzCY = 3;
        this.zzaRq = true;
        this.zzaRr = true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MaskedWalletRequest(int versionCode, String merchantTransactionId, boolean phoneNumberRequired, boolean shippingAddressRequired, boolean useMinimalBillingAddress, String estimatedTotalPrice, String currencyCode, String merchantName, Cart cart, boolean shouldRetrieveWalletObjects, boolean isBillingAgreement, CountrySpecification[] allowedShippingCountrySpecifications, boolean allowPrepaidCard, boolean allowDebitCard, ArrayList<com.google.android.gms.identity.intents.model.CountrySpecification> allowedCountrySpecificationsForShipping, PaymentMethodTokenizationParameters paymentMethodTokenizationParameters, ArrayList<Integer> allowedCardNetworks) {
        this.zzCY = versionCode;
        this.zzaQn = merchantTransactionId;
        this.zzaRi = phoneNumberRequired;
        this.zzaRj = shippingAddressRequired;
        this.zzaRk = useMinimalBillingAddress;
        this.zzaRl = estimatedTotalPrice;
        this.zzaQg = currencyCode;
        this.zzaRm = merchantName;
        this.zzaQx = cart;
        this.zzaRn = shouldRetrieveWalletObjects;
        this.zzaRo = isBillingAgreement;
        this.zzaRp = allowedShippingCountrySpecifications;
        this.zzaRq = allowPrepaidCard;
        this.zzaRr = allowDebitCard;
        this.zzaRs = allowedCountrySpecificationsForShipping;
        this.zzaRt = paymentMethodTokenizationParameters;
        this.zzaRu = allowedCardNetworks;
    }

    public static Builder newBuilder() {
        MaskedWalletRequest maskedWalletRequest = new MaskedWalletRequest();
        maskedWalletRequest.getClass();
        return new Builder();
    }

    public boolean allowDebitCard() {
        return this.zzaRr;
    }

    public boolean allowPrepaidCard() {
        return this.zzaRq;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public ArrayList<Integer> getAllowedCardNetworks() {
        return this.zzaRu;
    }

    public ArrayList<com.google.android.gms.identity.intents.model.CountrySpecification> getAllowedCountrySpecificationsForShipping() {
        return this.zzaRs;
    }

    public CountrySpecification[] getAllowedShippingCountrySpecifications() {
        return this.zzaRp;
    }

    public Cart getCart() {
        return this.zzaQx;
    }

    public String getCurrencyCode() {
        return this.zzaQg;
    }

    public String getEstimatedTotalPrice() {
        return this.zzaRl;
    }

    public String getMerchantName() {
        return this.zzaRm;
    }

    public String getMerchantTransactionId() {
        return this.zzaQn;
    }

    public PaymentMethodTokenizationParameters getPaymentMethodTokenizationParameters() {
        return this.zzaRt;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    public boolean isBillingAgreement() {
        return this.zzaRo;
    }

    public boolean isPhoneNumberRequired() {
        return this.zzaRi;
    }

    public boolean isShippingAddressRequired() {
        return this.zzaRj;
    }

    public boolean shouldRetrieveWalletObjects() {
        return this.zzaRn;
    }

    public boolean useMinimalBillingAddress() {
        return this.zzaRk;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzl.zza(this, dest, flags);
    }
}
