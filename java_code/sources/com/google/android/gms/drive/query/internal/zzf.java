package com.google.android.gms.drive.query.internal;

import com.google.android.gms.drive.metadata.MetadataField;
import java.util.List;
/* loaded from: classes.dex */
public interface zzf<F> {
    <T> F zzb(com.google.android.gms.drive.metadata.zzb<T> zzbVar, T t);

    <T> F zzb(Operator operator, MetadataField<T> metadataField, T t);

    F zzb(Operator operator, List<F> list);

    F zzcC(String str);

    <T> F zzd(MetadataField<T> metadataField, T t);

    F zze(MetadataField<?> metadataField);

    F zzqe();

    F zzqf();

    F zzv(F f);
}
