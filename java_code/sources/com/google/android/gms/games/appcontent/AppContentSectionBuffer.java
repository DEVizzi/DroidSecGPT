package com.google.android.gms.games.appcontent;

import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.data.zzf;
import java.util.ArrayList;
/* loaded from: classes.dex */
public final class AppContentSectionBuffer extends zzf<AppContentSection> {
    private final ArrayList<DataHolder> zzaoD;

    @Override // com.google.android.gms.common.data.AbstractDataBuffer, com.google.android.gms.common.data.DataBuffer, com.google.android.gms.common.api.Releasable
    public void release() {
        super.release();
        int size = this.zzaoD.size();
        for (int i = 1; i < size; i++) {
            DataHolder dataHolder = this.zzaoD.get(i);
            if (dataHolder != null) {
                dataHolder.close();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.data.zzf
    /* renamed from: zzm */
    public AppContentSection zzj(int i, int i2) {
        return new AppContentSectionRef(this.zzaoD, i, i2);
    }

    @Override // com.google.android.gms.common.data.zzf
    protected String zzni() {
        return "section_id";
    }

    @Override // com.google.android.gms.common.data.zzf
    protected String zznk() {
        return "card_id";
    }
}
