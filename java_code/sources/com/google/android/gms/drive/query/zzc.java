package com.google.android.gms.drive.query;

import com.google.android.gms.drive.metadata.MetadataField;
import com.google.android.gms.drive.query.internal.Operator;
import com.google.android.gms.drive.query.internal.zzf;
import java.util.Iterator;
import java.util.List;
/* loaded from: classes.dex */
public class zzc implements zzf<String> {
    public <T> String zza(com.google.android.gms.drive.metadata.zzb<T> zzbVar, T t) {
        return String.format("contains(%s,%s)", zzbVar.getName(), t);
    }

    @Override // com.google.android.gms.drive.query.internal.zzf
    /* renamed from: zza */
    public <T> String zzb(Operator operator, MetadataField<T> metadataField, T t) {
        return String.format("cmp(%s,%s,%s)", operator.getTag(), metadataField.getName(), t);
    }

    @Override // com.google.android.gms.drive.query.internal.zzf
    /* renamed from: zza */
    public String zzb(Operator operator, List<String> list) {
        StringBuilder sb = new StringBuilder(operator.getTag() + "(");
        String str = "";
        Iterator<String> it = list.iterator();
        while (true) {
            String str2 = str;
            if (!it.hasNext()) {
                return sb.append(")").toString();
            }
            sb.append(str2);
            sb.append(it.next());
            str = ",";
        }
    }

    @Override // com.google.android.gms.drive.query.internal.zzf
    public /* synthetic */ String zzb(com.google.android.gms.drive.metadata.zzb zzbVar, Object obj) {
        return zza((com.google.android.gms.drive.metadata.zzb<com.google.android.gms.drive.metadata.zzb>) zzbVar, (com.google.android.gms.drive.metadata.zzb) obj);
    }

    @Override // com.google.android.gms.drive.query.internal.zzf
    /* renamed from: zzc */
    public <T> String zzd(MetadataField<T> metadataField, T t) {
        return String.format("has(%s,%s)", metadataField.getName(), t);
    }

    @Override // com.google.android.gms.drive.query.internal.zzf
    /* renamed from: zzcA */
    public String zzv(String str) {
        return String.format("not(%s)", str);
    }

    @Override // com.google.android.gms.drive.query.internal.zzf
    /* renamed from: zzcB */
    public String zzcC(String str) {
        return String.format("fullTextSearch(%s)", str);
    }

    @Override // com.google.android.gms.drive.query.internal.zzf
    /* renamed from: zzd */
    public String zze(MetadataField<?> metadataField) {
        return String.format("fieldOnly(%s)", metadataField.getName());
    }

    @Override // com.google.android.gms.drive.query.internal.zzf
    /* renamed from: zzqc */
    public String zzqf() {
        return "all()";
    }

    @Override // com.google.android.gms.drive.query.internal.zzf
    /* renamed from: zzqd */
    public String zzqe() {
        return "ownedByMe()";
    }
}
