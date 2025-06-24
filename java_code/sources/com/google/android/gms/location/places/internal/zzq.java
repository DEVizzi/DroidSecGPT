package com.google.android.gms.location.places.internal;

import com.google.android.gms.common.data.DataHolder;
/* loaded from: classes.dex */
public class zzq extends zzt implements com.google.android.gms.location.places.zzg {
    private final String zzaAW;

    public zzq(DataHolder dataHolder, int i) {
        super(dataHolder, i);
        this.zzaAW = getString("photo_fife_url");
    }

    public CharSequence getAttributions() {
        return zzB("photo_attributions", null);
    }

    public int getMaxHeight() {
        return zzz("photo_max_height", 0);
    }

    public int getMaxWidth() {
        return zzz("photo_max_width", 0);
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzuZ */
    public com.google.android.gms.location.places.zzg freeze() {
        return new zzp(this.zzaAW, getMaxWidth(), getMaxHeight(), getAttributions(), this.zzYs);
    }
}
