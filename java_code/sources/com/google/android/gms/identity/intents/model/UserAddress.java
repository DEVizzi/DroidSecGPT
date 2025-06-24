package com.google.android.gms.identity.intents.model;

import android.content.Intent;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.identity.intents.AddressConstants;
/* loaded from: classes.dex */
public final class UserAddress implements SafeParcelable {
    public static final Parcelable.Creator<UserAddress> CREATOR = new zzb();
    String name;
    private final int zzCY;
    String zzEr;
    String zzawA;
    String zzawB;
    String zzawC;
    String zzawD;
    String zzawE;
    String zzawF;
    String zzawG;
    String zzawH;
    String zzawI;
    String zzawJ;
    boolean zzawK;
    String zzawL;
    String zzawM;

    UserAddress() {
        this.zzCY = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public UserAddress(int versionCode, String name, String address1, String address2, String address3, String address4, String address5, String administrativeArea, String locality, String countryCode, String postalCode, String sortingCode, String phoneNumber, boolean isPostBox, String companyName, String emailAddress) {
        this.zzCY = versionCode;
        this.name = name;
        this.zzawA = address1;
        this.zzawB = address2;
        this.zzawC = address3;
        this.zzawD = address4;
        this.zzawE = address5;
        this.zzawF = administrativeArea;
        this.zzawG = locality;
        this.zzEr = countryCode;
        this.zzawH = postalCode;
        this.zzawI = sortingCode;
        this.zzawJ = phoneNumber;
        this.zzawK = isPostBox;
        this.zzawL = companyName;
        this.zzawM = emailAddress;
    }

    public static UserAddress fromIntent(Intent data) {
        if (data == null || !data.hasExtra(AddressConstants.Extras.EXTRA_ADDRESS)) {
            return null;
        }
        return (UserAddress) data.getParcelableExtra(AddressConstants.Extras.EXTRA_ADDRESS);
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

    public String getAddress4() {
        return this.zzawD;
    }

    public String getAddress5() {
        return this.zzawE;
    }

    public String getAdministrativeArea() {
        return this.zzawF;
    }

    public String getCompanyName() {
        return this.zzawL;
    }

    public String getCountryCode() {
        return this.zzEr;
    }

    public String getEmailAddress() {
        return this.zzawM;
    }

    public String getLocality() {
        return this.zzawG;
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

    public String getSortingCode() {
        return this.zzawI;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    public boolean isPostBox() {
        return this.zzawK;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzb.zza(this, out, flags);
    }
}
