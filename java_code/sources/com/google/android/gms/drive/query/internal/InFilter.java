package com.google.android.gms.drive.query.internal;

import android.os.Parcel;
import com.google.android.gms.drive.metadata.SearchableCollectionMetadataField;
import com.google.android.gms.drive.metadata.internal.MetadataBundle;
import java.util.Collection;
import java.util.Collections;
/* loaded from: classes.dex */
public class InFilter<T> extends AbstractFilter {
    public static final zzj CREATOR = new zzj();
    final int zzCY;
    final MetadataBundle zzahR;
    private final com.google.android.gms.drive.metadata.zzb<T> zzaie;

    /* JADX INFO: Access modifiers changed from: package-private */
    public InFilter(int versionCode, MetadataBundle value) {
        this.zzCY = versionCode;
        this.zzahR = value;
        this.zzaie = (com.google.android.gms.drive.metadata.zzb) zze.zzb(value);
    }

    public InFilter(SearchableCollectionMetadataField<T> field, T value) {
        this(1, MetadataBundle.zza(field, Collections.singleton(value)));
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public T getValue() {
        return (T) ((Collection) this.zzahR.zza(this.zzaie)).iterator().next();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzj.zza(this, out, flags);
    }

    @Override // com.google.android.gms.drive.query.Filter
    public <F> F zza(zzf<F> zzfVar) {
        return zzfVar.zzb((com.google.android.gms.drive.metadata.zzb<com.google.android.gms.drive.metadata.zzb<T>>) this.zzaie, (com.google.android.gms.drive.metadata.zzb<T>) getValue());
    }
}
