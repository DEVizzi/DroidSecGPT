package com.google.android.gms.games.appcontent;

import android.os.Bundle;
import android.os.Parcel;
import com.google.android.gms.common.data.DataHolder;
import java.util.ArrayList;
import java.util.List;
/* loaded from: classes.dex */
public final class AppContentCardRef extends MultiDataBufferRef implements AppContentCard {
    /* JADX INFO: Access modifiers changed from: package-private */
    public AppContentCardRef(ArrayList<DataHolder> dataHolderCollection, int dataRow) {
        super(dataHolderCollection, 0, dataRow);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // com.google.android.gms.common.data.zzc
    public boolean equals(Object obj) {
        return AppContentCardEntity.zza(this, obj);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentCard
    public List<AppContentAction> getActions() {
        return AppContentUtils.zza(this.zzWu, this.zzaoD, "card_actions", this.zzYs);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentCard
    public String getDescription() {
        return getString("card_description");
    }

    @Override // com.google.android.gms.games.appcontent.AppContentCard
    public Bundle getExtras() {
        return AppContentUtils.zzd(this.zzWu, this.zzaoD, "card_data", this.zzYs);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentCard
    public String getId() {
        return getString("card_id");
    }

    @Override // com.google.android.gms.games.appcontent.AppContentCard
    public String getTitle() {
        return getString("card_title");
    }

    @Override // com.google.android.gms.games.appcontent.AppContentCard
    public String getType() {
        return getString("card_type");
    }

    @Override // com.google.android.gms.common.data.zzc
    public int hashCode() {
        return AppContentCardEntity.zza(this);
    }

    public String toString() {
        return AppContentCardEntity.zzb(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        ((AppContentCardEntity) freeze()).writeToParcel(dest, flags);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentCard
    public List<AppContentCondition> zzrO() {
        return AppContentUtils.zzc(this.zzWu, this.zzaoD, "card_conditions", this.zzYs);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentCard
    public String zzrP() {
        return getString("card_content_description");
    }

    @Override // com.google.android.gms.games.appcontent.AppContentCard
    public List<AppContentAnnotation> zzrZ() {
        return AppContentUtils.zzb(this.zzWu, this.zzaoD, "card_annotations", this.zzYs);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentCard
    public int zzsa() {
        return getInteger("card_current_steps");
    }

    @Override // com.google.android.gms.games.appcontent.AppContentCard
    public String zzsb() {
        return getString("card_subtitle");
    }

    @Override // com.google.android.gms.games.appcontent.AppContentCard
    public int zzsc() {
        return getInteger("card_total_steps");
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzsd */
    public AppContentCard freeze() {
        return new AppContentCardEntity(this);
    }
}
