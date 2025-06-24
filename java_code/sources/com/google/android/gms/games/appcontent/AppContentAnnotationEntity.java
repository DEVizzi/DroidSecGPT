package com.google.android.gms.games.appcontent;

import android.net.Uri;
import android.os.Bundle;
import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
/* loaded from: classes.dex */
public final class AppContentAnnotationEntity implements SafeParcelable, AppContentAnnotation {
    public static final AppContentAnnotationEntityCreator CREATOR = new AppContentAnnotationEntityCreator();
    private final int zzCY;
    private final String zzKI;
    private final String zzadv;
    private final String zzakM;
    private final Uri zzaop;
    private final String zzaoq;
    private final String zzaor;
    private final int zzaos;
    private final int zzaot;
    private final Bundle zzaou;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AppContentAnnotationEntity(int versionCode, String description, Uri imageUri, String title, String id, String layoutSlot, String imageDefaultId, int imageHeight, int imageWidth, Bundle modifiers) {
        this.zzCY = versionCode;
        this.zzakM = description;
        this.zzKI = id;
        this.zzaor = imageDefaultId;
        this.zzaos = imageHeight;
        this.zzaop = imageUri;
        this.zzaot = imageWidth;
        this.zzaoq = layoutSlot;
        this.zzaou = modifiers;
        this.zzadv = title;
    }

    public AppContentAnnotationEntity(AppContentAnnotation annotation) {
        this.zzCY = 4;
        this.zzakM = annotation.getDescription();
        this.zzKI = annotation.getId();
        this.zzaor = annotation.zzrS();
        this.zzaos = annotation.zzrT();
        this.zzaop = annotation.zzrU();
        this.zzaot = annotation.zzrW();
        this.zzaoq = annotation.zzrX();
        this.zzaou = annotation.zzrV();
        this.zzadv = annotation.getTitle();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int zza(AppContentAnnotation appContentAnnotation) {
        return zzt.hashCode(appContentAnnotation.getDescription(), appContentAnnotation.getId(), appContentAnnotation.zzrS(), Integer.valueOf(appContentAnnotation.zzrT()), appContentAnnotation.zzrU(), Integer.valueOf(appContentAnnotation.zzrW()), appContentAnnotation.zzrX(), appContentAnnotation.zzrV(), appContentAnnotation.getTitle());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean zza(AppContentAnnotation appContentAnnotation, Object obj) {
        if (obj instanceof AppContentAnnotation) {
            if (appContentAnnotation != obj) {
                AppContentAnnotation appContentAnnotation2 = (AppContentAnnotation) obj;
                return zzt.equal(appContentAnnotation2.getDescription(), appContentAnnotation.getDescription()) && zzt.equal(appContentAnnotation2.getId(), appContentAnnotation.getId()) && zzt.equal(appContentAnnotation2.zzrS(), appContentAnnotation.zzrS()) && zzt.equal(Integer.valueOf(appContentAnnotation2.zzrT()), Integer.valueOf(appContentAnnotation.zzrT())) && zzt.equal(appContentAnnotation2.zzrU(), appContentAnnotation.zzrU()) && zzt.equal(Integer.valueOf(appContentAnnotation2.zzrW()), Integer.valueOf(appContentAnnotation.zzrW())) && zzt.equal(appContentAnnotation2.zzrX(), appContentAnnotation.zzrX()) && zzt.equal(appContentAnnotation2.zzrV(), appContentAnnotation.zzrV()) && zzt.equal(appContentAnnotation2.getTitle(), appContentAnnotation.getTitle());
            }
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String zzb(AppContentAnnotation appContentAnnotation) {
        return zzt.zzt(appContentAnnotation).zzg("Description", appContentAnnotation.getDescription()).zzg("Id", appContentAnnotation.getId()).zzg("ImageDefaultId", appContentAnnotation.zzrS()).zzg("ImageHeight", Integer.valueOf(appContentAnnotation.zzrT())).zzg("ImageUri", appContentAnnotation.zzrU()).zzg("ImageWidth", Integer.valueOf(appContentAnnotation.zzrW())).zzg("LayoutSlot", appContentAnnotation.zzrX()).zzg("Modifiers", appContentAnnotation.zzrV()).zzg("Title", appContentAnnotation.getTitle()).toString();
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object obj) {
        return zza(this, obj);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAnnotation
    public String getDescription() {
        return this.zzakM;
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAnnotation
    public String getId() {
        return this.zzKI;
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAnnotation
    public String getTitle() {
        return this.zzadv;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return zza(this);
    }

    @Override // com.google.android.gms.common.data.Freezable
    public boolean isDataValid() {
        return true;
    }

    public String toString() {
        return zzb(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        AppContentAnnotationEntityCreator.zza(this, out, flags);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAnnotation
    public String zzrS() {
        return this.zzaor;
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAnnotation
    public int zzrT() {
        return this.zzaos;
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAnnotation
    public Uri zzrU() {
        return this.zzaop;
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAnnotation
    public Bundle zzrV() {
        return this.zzaou;
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAnnotation
    public int zzrW() {
        return this.zzaot;
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAnnotation
    public String zzrX() {
        return this.zzaoq;
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzrY */
    public AppContentAnnotation freeze() {
        return this;
    }
}
