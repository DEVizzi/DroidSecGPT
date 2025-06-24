package com.google.android.gms.wearable.internal;

import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.wearable.DataItemAsset;
/* loaded from: classes.dex */
public class zzz extends com.google.android.gms.common.data.zzc implements DataItemAsset {
    public zzz(DataHolder dataHolder, int i) {
        super(dataHolder, i);
    }

    @Override // com.google.android.gms.wearable.DataItemAsset
    public String getDataItemKey() {
        return getString("asset_key");
    }

    @Override // com.google.android.gms.wearable.DataItemAsset
    public String getId() {
        return getString("asset_id");
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzBd */
    public DataItemAsset freeze() {
        return new zzx(this);
    }
}
