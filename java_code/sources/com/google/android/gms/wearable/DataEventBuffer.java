package com.google.android.gms.wearable;

import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.wearable.internal.zzw;
/* loaded from: classes.dex */
public class DataEventBuffer extends com.google.android.gms.common.data.zzf<DataEvent> implements Result {
    private final Status zzOt;

    public DataEventBuffer(DataHolder dataHolder) {
        super(dataHolder);
        this.zzOt = new Status(dataHolder.getStatusCode());
    }

    @Override // com.google.android.gms.common.api.Result
    public Status getStatus() {
        return this.zzOt;
    }

    @Override // com.google.android.gms.common.data.zzf
    protected String zzni() {
        return "path";
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.data.zzf
    /* renamed from: zzu */
    public DataEvent zzj(int i, int i2) {
        return new zzw(this.zzWu, i, i2);
    }
}
