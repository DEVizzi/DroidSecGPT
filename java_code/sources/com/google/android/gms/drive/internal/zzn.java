package com.google.android.gms.drive.internal;

import com.google.android.gms.drive.Metadata;
import com.google.android.gms.drive.metadata.MetadataField;
import com.google.android.gms.drive.metadata.internal.MetadataBundle;
/* loaded from: classes.dex */
public final class zzn extends Metadata {
    private final MetadataBundle zzaeF;

    public zzn(MetadataBundle metadataBundle) {
        this.zzaeF = metadataBundle;
    }

    @Override // com.google.android.gms.common.data.Freezable
    public boolean isDataValid() {
        return this.zzaeF != null;
    }

    public String toString() {
        return "Metadata [mImpl=" + this.zzaeF + "]";
    }

    @Override // com.google.android.gms.drive.Metadata
    public <T> T zza(MetadataField<T> metadataField) {
        return (T) this.zzaeF.zza(metadataField);
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzpl */
    public Metadata freeze() {
        return new zzn(MetadataBundle.zza(this.zzaeF));
    }
}
