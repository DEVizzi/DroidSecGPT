package com.google.android.gms.internal;

import com.google.android.gms.internal.zzm;
import java.io.UnsupportedEncodingException;
/* loaded from: classes.dex */
public class zzab extends zzk<String> {
    private final zzm.zzb<String> zzaH;

    public zzab(int i, String str, zzm.zzb<String> zzbVar, zzm.zza zzaVar) {
        super(i, str, zzaVar);
        this.zzaH = zzbVar;
    }

    public zzab(String str, zzm.zzb<String> zzbVar, zzm.zza zzaVar) {
        this(0, str, zzbVar, zzaVar);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.internal.zzk
    public zzm<String> zza(zzi zziVar) {
        String str;
        try {
            str = new String(zziVar.data, zzx.zza(zziVar.zzA));
        } catch (UnsupportedEncodingException e) {
            str = new String(zziVar.data);
        }
        return zzm.zza(str, zzx.zzb(zziVar));
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.internal.zzk
    /* renamed from: zzi */
    public void zza(String str) {
        this.zzaH.zzb(str);
    }
}
