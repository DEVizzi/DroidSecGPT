package com.google.android.gms.wallet;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
@Deprecated
/* loaded from: classes.dex */
public final class Address implements SafeParcelable {
    public static final Parcelable.Creator<Address> CREATOR = new zza();
    String name;
    private final int zzCY;
    String zzEr;
    String zzaQd;
    String zzaQe;
    String zzawA;
    String zzawB;
    String zzawC;
    String zzawH;
    String zzawJ;
    boolean zzawK;
    String zzawL;

    Address() {
        this.zzCY = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Address(int versionCode, String name, String address1, String address2, String address3, String countryCode, String city, String state, String postalCode, String phoneNumber, boolean isPostBox, String companyName) {
        this.zzCY = versionCode;
        this.name = name;
        this.zzawA = address1;
        this.zzawB = address2;
        this.zzawC = address3;
        this.zzEr = countryCode;
        this.zzaQd = city;
        this.zzaQe = state;
        this.zzawH = postalCode;
        this.zzawJ = phoneNumber;
        this.zzawK = isPostBox;
        this.zzawL = companyName;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String getAddress1() {
        return this.zzawA;
    }

    public String getAddress2() {
        return this.zzawB;
    }

    public String getAddress3() {
        return this.zzawC;
    }

    public String getCity() {
        return this.zzaQd;
    }

    public String getCompanyName() {
        return this.zzawL;
    }

    public String getCountryCode() {
        return this.zzEr;
    }

    public String getName() {
        return this.name;
    }

    public String getPhoneNumber() {
        return this.zzawJ;
    }

    public String getPostalCode() {
        return this.zzawH;
    }

    public String getState() {
        return this.zzaQe;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    public boolean isPostBox() {
        return this.zzawK;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zza.zza(this, out, flags);
    }
}
