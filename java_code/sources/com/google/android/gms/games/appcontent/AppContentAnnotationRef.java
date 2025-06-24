package com.google.android.gms.games.appcontent;

import android.net.Uri;
import android.os.Bundle;
import android.os.Parcel;
import com.google.android.gms.common.data.DataHolder;
import java.util.ArrayList;
/* loaded from: classes.dex */
public final class AppContentAnnotationRef extends MultiDataBufferRef implements AppContentAnnotation {
    /* JADX INFO: Access modifiers changed from: package-private */
    public AppContentAnnotationRef(ArrayList<DataHolder> dataHolders, int dataRow) {
        super(dataHolders, 2, dataRow);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // com.google.android.gms.common.data.zzc
    public boolean equals(Object obj) {
        return AppContentAnnotationEntity.zza(this, obj);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAnnotation
    public String getDescription() {
        return getString("annotation_description");
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAnnotation
    public String getId() {
        return getString("annotation_id");
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAnnotation
    public String getTitle() {
        return getString("annotation_title");
    }

    @Override // com.google.android.gms.common.data.zzc
    public int hashCode() {
        return AppContentAnnotationEntity.zza(this);
    }

    public String toString() {
        return AppContentAnnotationEntity.zzb(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        ((AppContentAnnotationEntity) freeze()).writeToParcel(dest, flags);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAnnotation
    public String zzrS() {
        return getString("annotation_image_default_id");
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAnnotation
    public int zzrT() {
        return getInteger("annotation_image_height");
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAnnotation
    public Uri zzrU() {
        return zzbW("annotation_image_uri");
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAnnotation
    public Bundle zzrV() {
        return AppContentUtils.zzd(this.zzWu, this.zzaoD, "annotation_modifiers", this.zzYs);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAnnotation
    public int zzrW() {
        return getInteger("annotation_image_width");
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAnnotation
    public String zzrX() {
        return getString("annotation_layout_slot");
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzrY */
    public AppContentAnnotation freeze() {
        return new AppContentAnnotationEntity(this);
    }
}
