package com.google.android.gms.games.appcontent;

import android.os.Bundle;
import android.os.Parcel;
import com.google.android.gms.common.data.DataHolder;
import java.util.ArrayList;
import java.util.List;
/* loaded from: classes.dex */
public final class AppContentActionRef extends MultiDataBufferRef implements AppContentAction {
    /* JADX INFO: Access modifiers changed from: package-private */
    public AppContentActionRef(ArrayList<DataHolder> dataHolderCollection, int dataRow) {
        super(dataHolderCollection, 1, dataRow);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // com.google.android.gms.common.data.zzc
    public boolean equals(Object obj) {
        return AppContentActionEntity.zza(this, obj);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAction
    public Bundle getExtras() {
        return AppContentUtils.zzd(this.zzWu, this.zzaoD, "action_data", this.zzYs);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAction
    public String getId() {
        return getString("action_id");
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAction
    public String getType() {
        return getString("action_type");
    }

    @Override // com.google.android.gms.common.data.zzc
    public int hashCode() {
        return AppContentActionEntity.zza(this);
    }

    public String toString() {
        return AppContentActionEntity.zzb(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        ((AppContentActionEntity) freeze()).writeToParcel(dest, flags);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAction
    public AppContentAnnotation zzrN() {
        ArrayList<AppContentAnnotation> zzb = AppContentUtils.zzb(this.zzWu, this.zzaoD, "action_annotation", this.zzYs);
        if (zzb.size() == 1) {
            return zzb.get(0);
        }
        return null;
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAction
    public List<AppContentCondition> zzrO() {
        return AppContentUtils.zzc(this.zzWu, this.zzaoD, "action_conditions", this.zzYs);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAction
    public String zzrP() {
        return getString("action_content_description");
    }

    @Override // com.google.android.gms.games.appcontent.AppContentAction
    public String zzrQ() {
        return getString("overflow_text");
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzrR */
    public AppContentAction freeze() {
        return new AppContentActionEntity(this);
    }
}
