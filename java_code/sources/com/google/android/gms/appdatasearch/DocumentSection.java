package com.google.android.gms.appdatasearch;

import android.os.Parcel;
import com.google.android.gms.appdatasearch.RegisterSectionInfo;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
/* loaded from: classes.dex */
public class DocumentSection implements SafeParcelable {
    final int zzCY;
    public final String zzNe;
    final RegisterSectionInfo zzNf;
    public final int zzNg;
    public final byte[] zzNh;
    public static final int zzNc = Integer.parseInt("-1");
    public static final zzd CREATOR = new zzd();
    private static final RegisterSectionInfo zzNd = new RegisterSectionInfo.zza("SsbContext").zzJ(true).zzbr("blob").zzkM();

    /* JADX INFO: Access modifiers changed from: package-private */
    public DocumentSection(int versionCode, String content, RegisterSectionInfo sectionInfo, int globalSearchSectionType, byte[] blobContent) {
        zzu.zzb(globalSearchSectionType == zzNc || zzh.zzai(globalSearchSectionType) != null, "Invalid section type " + globalSearchSectionType);
        this.zzCY = versionCode;
        this.zzNe = content;
        this.zzNf = sectionInfo;
        this.zzNg = globalSearchSectionType;
        this.zzNh = blobContent;
        String zzkK = zzkK();
        if (zzkK != null) {
            throw new IllegalArgumentException(zzkK);
        }
    }

    public DocumentSection(String content, RegisterSectionInfo sectionInfo) {
        this(1, content, sectionInfo, zzNc, null);
    }

    public DocumentSection(String content, RegisterSectionInfo sectionInfo, String globalSearchSectionType) {
        this(1, content, sectionInfo, zzh.zzbq(globalSearchSectionType), null);
    }

    public DocumentSection(byte[] blobContent, RegisterSectionInfo sectionInfo) {
        this(1, null, sectionInfo, zzNc, blobContent);
    }

    public static DocumentSection zzh(byte[] bArr) {
        return new DocumentSection(bArr, zzNd);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zzd zzdVar = CREATOR;
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzd zzdVar = CREATOR;
        zzd.zza(this, dest, flags);
    }

    public String zzkK() {
        if (this.zzNg == zzNc || zzh.zzai(this.zzNg) != null) {
            if (this.zzNe == null || this.zzNh == null) {
                return null;
            }
            return "Both content and blobContent set";
        }
        return "Invalid section type " + this.zzNg;
    }
}
