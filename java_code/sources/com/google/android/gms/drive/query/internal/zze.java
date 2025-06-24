package com.google.android.gms.drive.query.internal;

import com.google.android.gms.drive.metadata.MetadataField;
import com.google.android.gms.drive.metadata.internal.MetadataBundle;
import java.util.Set;
/* loaded from: classes.dex */
class zze {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static MetadataField<?> zzb(MetadataBundle metadataBundle) {
        Set<MetadataField<?>> zzpY = metadataBundle.zzpY();
        if (zzpY.size() != 1) {
            throw new IllegalArgumentException("bundle should have exactly 1 populated field");
        }
        return zzpY.iterator().next();
    }
}
