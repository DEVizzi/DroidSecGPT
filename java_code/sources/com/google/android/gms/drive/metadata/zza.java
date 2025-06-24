package com.google.android.gms.drive.metadata;

import android.os.Bundle;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.drive.metadata.internal.MetadataBundle;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
/* loaded from: classes.dex */
public abstract class zza<T> implements MetadataField<T> {
    private final Set<String> zzagA;
    private final int zzagB;
    private final String zzagy;
    private final Set<String> zzagz;

    /* JADX INFO: Access modifiers changed from: protected */
    public zza(String str, int i) {
        this.zzagy = (String) zzu.zzb(str, "fieldName");
        this.zzagz = Collections.singleton(str);
        this.zzagA = Collections.emptySet();
        this.zzagB = i;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public zza(String str, Collection<String> collection, Collection<String> collection2, int i) {
        this.zzagy = (String) zzu.zzb(str, "fieldName");
        this.zzagz = Collections.unmodifiableSet(new HashSet(collection));
        this.zzagA = Collections.unmodifiableSet(new HashSet(collection2));
        this.zzagB = i;
    }

    @Override // com.google.android.gms.drive.metadata.MetadataField
    public final String getName() {
        return this.zzagy;
    }

    public String toString() {
        return this.zzagy;
    }

    @Override // com.google.android.gms.drive.metadata.MetadataField
    public final T zza(DataHolder dataHolder, int i, int i2) {
        if (zzb(dataHolder, i, i2)) {
            return zzc(dataHolder, i, i2);
        }
        return null;
    }

    protected abstract void zza(Bundle bundle, T t);

    @Override // com.google.android.gms.drive.metadata.MetadataField
    public final void zza(DataHolder dataHolder, MetadataBundle metadataBundle, int i, int i2) {
        zzu.zzb(dataHolder, "dataHolder");
        zzu.zzb(metadataBundle, "bundle");
        if (zzb(dataHolder, i, i2)) {
            metadataBundle.zzb(this, zzc(dataHolder, i, i2));
        }
    }

    @Override // com.google.android.gms.drive.metadata.MetadataField
    public final void zza(T t, Bundle bundle) {
        zzu.zzb(bundle, "bundle");
        if (t == null) {
            bundle.putString(getName(), null);
        } else {
            zza(bundle, (Bundle) t);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:5:0x000c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    protected boolean zzb(com.google.android.gms.common.data.DataHolder r4, int r5, int r6) {
        /*
            r3 = this;
            java.util.Set<java.lang.String> r0 = r3.zzagz
            java.util.Iterator r1 = r0.iterator()
        L6:
            boolean r0 = r1.hasNext()
            if (r0 == 0) goto L20
            java.lang.Object r0 = r1.next()
            java.lang.String r0 = (java.lang.String) r0
            boolean r2 = r4.zzbV(r0)
            if (r2 == 0) goto L1e
            boolean r0 = r4.zzi(r0, r5, r6)
            if (r0 == 0) goto L6
        L1e:
            r0 = 0
        L1f:
            return r0
        L20:
            r0 = 1
            goto L1f
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.drive.metadata.zza.zzb(com.google.android.gms.common.data.DataHolder, int, int):boolean");
    }

    protected abstract T zzc(DataHolder dataHolder, int i, int i2);

    @Override // com.google.android.gms.drive.metadata.MetadataField
    public final T zzi(Bundle bundle) {
        zzu.zzb(bundle, "bundle");
        if (bundle.get(getName()) != null) {
            return zzj(bundle);
        }
        return null;
    }

    protected abstract T zzj(Bundle bundle);
}
