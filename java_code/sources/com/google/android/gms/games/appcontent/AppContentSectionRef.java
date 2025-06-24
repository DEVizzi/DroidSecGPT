package com.google.android.gms.games.appcontent;

import android.os.Bundle;
import android.os.Parcel;
import com.google.android.gms.common.data.DataHolder;
import java.util.ArrayList;
/* loaded from: classes.dex */
public final class AppContentSectionRef extends MultiDataBufferRef implements AppContentSection {
    private final int zzaoG;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AppContentSectionRef(ArrayList<DataHolder> dataHolderCollection, int dataRow, int numChildren) {
        super(dataHolderCollection, 0, dataRow);
        this.zzaoG = numChildren;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // com.google.android.gms.common.data.zzc
    public boolean equals(Object obj) {
        return AppContentSectionEntity.zza(this, obj);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    public Bundle getExtras() {
        return AppContentUtils.zzd(this.zzWu, this.zzaoD, "section_data", this.zzYs);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    public String getId() {
        return getString("section_id");
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    public String getTitle() {
        return getString("section_title");
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    public String getType() {
        return getString("section_type");
    }

    @Override // com.google.android.gms.common.data.zzc
    public int hashCode() {
        return AppContentSectionEntity.zza(this);
    }

    public String toString() {
        return AppContentSectionEntity.zzb(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        ((AppContentSectionEntity) freeze()).writeToParcel(dest, flags);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    public String zzrP() {
        return getString("section_content_description");
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    public String zzsb() {
        return getString("section_subtitle");
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    public String zzsk() {
        return getString("section_card_type");
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzsl */
    public AppContentSection freeze() {
        return new AppContentSectionEntity(this);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    /* renamed from: zzsm */
    public ArrayList<AppContentAction> getActions() {
        return AppContentUtils.zza(this.zzWu, this.zzaoD, "section_actions", this.zzYs);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    /* renamed from: zzsn */
    public ArrayList<AppContentAnnotation> zzrZ() {
        return AppContentUtils.zzb(this.zzWu, this.zzaoD, "section_annotations", this.zzYs);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    /* renamed from: zzso */
    public ArrayList<AppContentCard> zzsj() {
        ArrayList<AppContentCard> arrayList = new ArrayList<>(this.zzaoG);
        for (int i = 0; i < this.zzaoG; i++) {
            arrayList.add(new AppContentCardRef(this.zzaoD, this.zzYs + i));
        }
        return arrayList;
    }
}
