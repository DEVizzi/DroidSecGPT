package com.google.android.gms.drive.query.internal;

import com.google.android.gms.drive.metadata.MetadataField;
import com.google.android.gms.drive.query.Filter;
import java.util.List;
/* loaded from: classes.dex */
public class zzg implements zzf<Boolean> {
    private Boolean zzaid = false;

    private zzg() {
    }

    public static boolean zza(Filter filter) {
        if (filter == null) {
            return false;
        }
        return ((Boolean) filter.zza(new zzg())).booleanValue();
    }

    @Override // com.google.android.gms.drive.query.internal.zzf
    public /* synthetic */ Boolean zzb(com.google.android.gms.drive.metadata.zzb zzbVar, Object obj) {
        return zzc((com.google.android.gms.drive.metadata.zzb<com.google.android.gms.drive.metadata.zzb>) zzbVar, (com.google.android.gms.drive.metadata.zzb) obj);
    }

    public <T> Boolean zzc(com.google.android.gms.drive.metadata.zzb<T> zzbVar, T t) {
        return this.zzaid;
    }

    @Override // com.google.android.gms.drive.query.internal.zzf
    /* renamed from: zzc */
    public <T> Boolean zzb(Operator operator, MetadataField<T> metadataField, T t) {
        return this.zzaid;
    }

    @Override // com.google.android.gms.drive.query.internal.zzf
    /* renamed from: zzc */
    public Boolean zzb(Operator operator, List<Boolean> list) {
        return this.zzaid;
    }

    @Override // com.google.android.gms.drive.query.internal.zzf
    /* renamed from: zzcD */
    public Boolean zzcC(String str) {
        if (!str.isEmpty()) {
            this.zzaid = true;
        }
        return this.zzaid;
    }

    @Override // com.google.android.gms.drive.query.internal.zzf
    /* renamed from: zzd */
    public Boolean zzv(Boolean bool) {
        return this.zzaid;
    }

    @Override // com.google.android.gms.drive.query.internal.zzf
    /* renamed from: zze */
    public <T> Boolean zzd(MetadataField<T> metadataField, T t) {
        return this.zzaid;
    }

    @Override // com.google.android.gms.drive.query.internal.zzf
    /* renamed from: zzf */
    public Boolean zze(MetadataField<?> metadataField) {
        return this.zzaid;
    }

    @Override // com.google.android.gms.drive.query.internal.zzf
    /* renamed from: zzqg */
    public Boolean zzqf() {
        return this.zzaid;
    }

    @Override // com.google.android.gms.drive.query.internal.zzf
    /* renamed from: zzqh */
    public Boolean zzqe() {
        return this.zzaid;
    }
}
