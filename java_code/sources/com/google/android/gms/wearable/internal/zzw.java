package com.google.android.gms.wearable.internal;

import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.wearable.DataEvent;
import com.google.android.gms.wearable.DataItem;
/* loaded from: classes.dex */
public final class zzw extends com.google.android.gms.common.data.zzc implements DataEvent {
    private final int zzaoG;

    public zzw(DataHolder dataHolder, int i, int i2) {
        super(dataHolder, i);
        this.zzaoG = i2;
    }

    @Override // com.google.android.gms.wearable.DataEvent
    public DataItem getDataItem() {
        return new zzac(this.zzWu, this.zzYs, this.zzaoG);
    }

    @Override // com.google.android.gms.wearable.DataEvent
    public int getType() {
        return getInteger("event_type");
    }

    public String toString() {
        return "DataEventRef{ type=" + (getType() == 1 ? "changed" : getType() == 2 ? "deleted" : "unknown") + ", dataitem=" + getDataItem() + " }";
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzBc */
    public DataEvent freeze() {
        return new zzv(this);
    }
}
