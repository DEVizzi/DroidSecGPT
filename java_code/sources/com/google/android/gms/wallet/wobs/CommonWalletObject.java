package com.google.android.gms.wallet.wobs;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.internal.zzkx;
import com.google.android.gms.maps.model.LatLng;
import java.util.ArrayList;
/* loaded from: classes.dex */
public class CommonWalletObject implements SafeParcelable {
    public static final Parcelable.Creator<CommonWalletObject> CREATOR = new com.google.android.gms.wallet.wobs.zza();
    String name;
    int state;
    private final int zzCY;
    String zzaQN;
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
    String zzhI;

    /* loaded from: classes.dex */
    public final class zza {
        private zza() {
        }

        public CommonWalletObject zzAO() {
            return CommonWalletObject.this;
        }

        public zza zzff(String str) {
            CommonWalletObject.this.zzhI = str;
            return this;
        }
    }

    CommonWalletObject() {
        this.zzCY = 1;
        this.zzaQU = zzkx.zzoP();
        this.zzaQW = zzkx.zzoP();
        this.zzaQZ = zzkx.zzoP();
        this.zzaRb = zzkx.zzoP();
        this.zzaRc = zzkx.zzoP();
        this.zzaRd = zzkx.zzoP();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CommonWalletObject(int versionCode, String id, String classId, String name, String issuerName, String barcodeAlternateText, String barcodeType, String barcodeValue, String barcodeLabel, int state, ArrayList<WalletObjectMessage> messages, TimeInterval validTimeInterval, ArrayList<LatLng> locations, String infoModuleDataHexFontColor, String infoModuleDataHexBackgroundColor, ArrayList<LabelValueRow> infoModuleDataLabelValueRows, boolean infoModuleDataShowLastUpdateTime, ArrayList<UriData> imageModuleDataMainImageUris, ArrayList<TextModuleData> textModulesData, ArrayList<UriData> linksModuleDataUris) {
        this.zzCY = versionCode;
        this.zzhI = id;
        this.zzaQT = classId;
        this.name = name;
        this.zzaQN = issuerName;
        this.zzaQP = barcodeAlternateText;
        this.zzaQQ = barcodeType;
        this.zzaQR = barcodeValue;
        this.zzaQS = barcodeLabel;
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
    }

    public static zza zzAN() {
        CommonWalletObject commonWalletObject = new CommonWalletObject();
        commonWalletObject.getClass();
        return new zza();
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String getId() {
        return this.zzhI;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        com.google.android.gms.wallet.wobs.zza.zza(this, dest, flags);
    }
}
