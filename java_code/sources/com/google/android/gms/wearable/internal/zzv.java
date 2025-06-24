package com.google.android.gms.wearable.internal;

import com.google.android.gms.wearable.DataEvent;
import com.google.android.gms.wearable.DataItem;
/* loaded from: classes.dex */
public class zzv implements DataEvent {
    private int zzSq;
    private DataItem zzaUl;

    public zzv(DataEvent dataEvent) {
        this.zzSq = dataEvent.getType();
        this.zzaUl = dataEvent.getDataItem().freeze();
    }

    @Override // com.google.android.gms.wearable.DataEvent
    public DataItem getDataItem() {
        return this.zzaUl;
    }

    @Override // com.google.android.gms.wearable.DataEvent
    public int getType() {
        return this.zzSq;
    }

    @Override // com.google.android.gms.common.data.Freezable
    public boolean isDataValid() {
        return true;
    }

    public String toString() {
        return "DataEventEntity{ type=" + (getType() == 1 ? "changed" : getType() == 2 ? "deleted" : "unknown") + ", dataitem=" + getDataItem() + " }";
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzBc */
    public DataEvent freeze() {
        return this;
    }
}
