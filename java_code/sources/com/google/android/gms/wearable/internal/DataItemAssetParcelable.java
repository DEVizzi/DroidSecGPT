package com.google.android.gms.wearable.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.wearable.DataItemAsset;
/* loaded from: classes.dex */
public class DataItemAssetParcelable implements SafeParcelable, DataItemAsset {
    public static final Parcelable.Creator<DataItemAssetParcelable> CREATOR = new zzy();
    final int zzCY;
    private final String zzKI;
    private final String zztw;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DataItemAssetParcelable(int versionCode, String id, String key) {
        this.zzCY = versionCode;
        this.zzKI = id;
        this.zztw = key;
    }

    public DataItemAssetParcelable(DataItemAsset value) {
        this.zzCY = 1;
        this.zzKI = (String) com.google.android.gms.common.internal.zzu.zzu(value.getId());
        this.zztw = (String) com.google.android.gms.common.internal.zzu.zzu(value.getDataItemKey());
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // com.google.android.gms.wearable.DataItemAsset
    public String getDataItemKey() {
        return this.zztw;
    }

    @Override // com.google.android.gms.wearable.DataItemAsset
    public String getId() {
        return this.zzKI;
    }

    @Override // com.google.android.gms.common.data.Freezable
    public boolean isDataValid() {
        return true;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("DataItemAssetParcelable[");
        sb.append("@");
        sb.append(Integer.toHexString(hashCode()));
        if (this.zzKI == null) {
            sb.append(",noid");
        } else {
            sb.append(",");
            sb.append(this.zzKI);
        }
        sb.append(", key=");
        sb.append(this.zztw);
        sb.append("]");
        return sb.toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzy.zza(this, dest, flags);
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzBd */
    public DataItemAsset freeze() {
        return this;
    }
}
