package com.google.android.gms.drive.metadata;

import android.os.Bundle;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.drive.metadata.internal.MetadataBundle;
/* loaded from: classes.dex */
public interface MetadataField<T> {
    String getName();

    T zza(DataHolder dataHolder, int i, int i2);

    void zza(DataHolder dataHolder, MetadataBundle metadataBundle, int i, int i2);

    void zza(T t, Bundle bundle);

    T zzi(Bundle bundle);
}
