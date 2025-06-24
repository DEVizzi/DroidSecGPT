package com.google.android.gms.wallet;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.internal.zzkx;
import com.google.android.gms.maps.model.LatLng;
import com.google.android.gms.wallet.wobs.LabelValueRow;
import com.google.android.gms.wallet.wobs.LoyaltyPoints;
import com.google.android.gms.wallet.wobs.TextModuleData;
import com.google.android.gms.wallet.wobs.TimeInterval;
import com.google.android.gms.wallet.wobs.UriData;
import com.google.android.gms.wallet.wobs.WalletObjectMessage;
import java.util.ArrayList;
/* loaded from: classes.dex */
public final class LoyaltyWalletObject implements SafeParcelable {
    public static final Parcelable.Creator<LoyaltyWalletObject> CREATOR = new zzj();
    int state;
    private final int zzCY;
    String zzaBb;
    String zzaQM;
    String zzaQN;
    String zzaQO;
    String zzaQP;
    String zzaQQ;
    String zzaQR;
    String zzaQS;
    String zzaQT;
    ArrayList<WalletObjectMessage> zzaQU;
    TimeInterval zzaQV;
    ArrayList<LatLng> zzaQW;
    String zzaQX;
    String zzaQY;
    ArrayList<LabelValueRow> zzaQZ;
    boolean zzaRa;
    ArrayList<UriData> zzaRb;
    ArrayList<TextModuleData> zzaRc;
    ArrayList<UriData> zzaRd;
    LoyaltyPoints zzaRe;
    String zzhI;

    LoyaltyWalletObject() {
        this.zzCY = 4;
        this.zzaQU = zzkx.zzoP();
        this.zzaQW = zzkx.zzoP();
        this.zzaQZ = zzkx.zzoP();
        this.zzaRb = zzkx.zzoP();
        this.zzaRc = zzkx.zzoP();
        this.zzaRd = zzkx.zzoP();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LoyaltyWalletObject(int versionCode, String id, String accountId, String issuerName, String programName, String accountName, String barcodeAlternateText, String barcodeType, String barcodeValue, String barcodeLabel, String classId, int state, ArrayList<WalletObjectMessage> messages, TimeInterval validTimeInterval, ArrayList<LatLng> locations, String infoModuleDataHexFontColor, String infoModuleDataHexBackgroundColor, ArrayList<LabelValueRow> infoModuleDataLabelValueRows, boolean infoModuleDataShowLastUpdateTime, ArrayList<UriData> imageModuleDataMainImageUris, ArrayList<TextModuleData> textModulesData, ArrayList<UriData> linksModuleDataUris, LoyaltyPoints loyaltyPoints) {
        this.zzCY = versionCode;
        this.zzhI = id;
        this.zzaQM = accountId;
        this.zzaQN = issuerName;
        this.zzaQO = programName;
        this.zzaBb = accountName;
        this.zzaQP = barcodeAlternateText;
        this.zzaQQ = barcodeType;
        this.zzaQR = barcodeValue;
        this.zzaQS = barcodeLabel;
        this.zzaQT = classId;
        this.state = state;
        this.zzaQU = messages;
        this.zzaQV = validTimeInterval;
        this.zzaQW = locations;
        this.zzaQX = infoModuleDataHexFontColor;
        this.zzaQY = infoModuleDataHexBackgroundColor;
        this.zzaQZ = infoModuleDataLabelValueRows;
        this.zzaRa = infoModuleDataShowLastUpdateTime;
        this.zzaRb = imageModuleDataMainImageUris;
        this.zzaRc = textModulesData;
        this.zzaRd = linksModuleDataUris;
        this.zzaRe = loyaltyPoints;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String getAccountId() {
        return this.zzaQM;
    }

    public String getAccountName() {
        return this.zzaBb;
    }

    public String getBarcodeAlternateText() {
        return this.zzaQP;
    }

    public String getBarcodeType() {
        return this.zzaQQ;
    }

    public String getBarcodeValue() {
        return this.zzaQR;
    }

    public String getId() {
        return this.zzhI;
    }

    public String getIssuerName() {
        return this.zzaQN;
    }

    public String getProgramName() {
        return this.zzaQO;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzj.zza(this, dest, flags);
    }
}
