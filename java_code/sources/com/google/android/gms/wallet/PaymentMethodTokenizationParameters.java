package com.google.android.gms.wallet;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
/* loaded from: classes.dex */
public final class PaymentMethodTokenizationParameters implements SafeParcelable {
    public static final Parcelable.Creator<PaymentMethodTokenizationParameters> CREATOR = new zzp();
    private final int zzCY;
    Bundle zzaDN;
    int zzaRz;

    /* loaded from: classes.dex */
    public final class Builder {
        private Builder() {
        }

        public Builder addParameter(String name, String value) {
            zzu.zzh(name, "Tokenization parameter name must not be empty");
            zzu.zzh(value, "Tokenization parameter value must not be empty");
            PaymentMethodTokenizationParameters.this.zzaDN.putString(name, value);
            return this;
        }

        public PaymentMethodTokenizationParameters build() {
            return PaymentMethodTokenizationParameters.this;
        }

        public Builder setPaymentMethodTokenizationType(int tokenizationType) {
            PaymentMethodTokenizationParameters.this.zzaRz = tokenizationType;
            return this;
        }
    }

    private PaymentMethodTokenizationParameters() {
        this.zzaDN = new Bundle();
        this.zzCY = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public PaymentMethodTokenizationParameters(int versionCode, int tokenizationType, Bundle parameters) {
        this.zzaDN = new Bundle();
        this.zzCY = versionCode;
        this.zzaRz = tokenizationType;
        this.zzaDN = parameters;
    }

    public static Builder newBuilder() {
        PaymentMethodTokenizationParameters paymentMethodTokenizationParameters = new PaymentMethodTokenizationParameters();
        paymentMethodTokenizationParameters.getClass();
        return new Builder();
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public Bundle getParameters() {
        return new Bundle(this.zzaDN);
    }

    public int getPaymentMethodTokenizationType() {
        return this.zzaRz;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzp.zza(this, out, flags);
    }
}
