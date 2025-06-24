package com.google.android.gms.internal;

import android.content.Context;
import com.google.android.gms.internal.zzm;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Map;
@zzgd
/* loaded from: classes.dex */
public class zzho {
    private static zzl zzGu;
    private static final Object zzoW = new Object();
    public static final zza<Void> zzGv = new zza() { // from class: com.google.android.gms.internal.zzho.1
        @Override // com.google.android.gms.internal.zzho.zza
        /* renamed from: zzgu */
        public Void zzft() {
            return null;
        }

        @Override // com.google.android.gms.internal.zzho.zza
        /* renamed from: zzi */
        public Void zzh(InputStream inputStream) {
            return null;
        }
    };

    /* loaded from: classes.dex */
    public interface zza<T> {
        T zzft();

        T zzh(InputStream inputStream);
    }

    /* loaded from: classes.dex */
    private static class zzb<T> extends zzk<InputStream> {
        private final zza<T> zzGz;
        private final zzm.zzb<T> zzaH;

        public zzb(String str, final zza<T> zzaVar, final zzm.zzb<T> zzbVar) {
            super(0, str, new zzm.zza() { // from class: com.google.android.gms.internal.zzho.zzb.1
                /* JADX WARN: Multi-variable type inference failed */
                @Override // com.google.android.gms.internal.zzm.zza
                public void zze(zzr zzrVar) {
                    zzm.zzb.this.zzb(zzaVar.zzft());
                }
            });
            this.zzGz = zzaVar;
            this.zzaH = zzbVar;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.internal.zzk
        public zzm<InputStream> zza(zzi zziVar) {
            return zzm.zza(new ByteArrayInputStream(zziVar.data), zzx.zzb(zziVar));
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.internal.zzk
        /* renamed from: zzj */
        public void zza(InputStream inputStream) {
            this.zzaH.zzb(this.zzGz.zzh(inputStream));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class zzc<T> extends zzhs<T> implements zzm.zzb<T> {
        private zzc() {
        }

        @Override // com.google.android.gms.internal.zzm.zzb
        public void zzb(T t) {
            super.zzf(t);
        }
    }

    public zzho(Context context) {
        zzGu = zzN(context);
    }

    private static zzl zzN(Context context) {
        zzl zzlVar;
        synchronized (zzoW) {
            if (zzGu == null) {
                zzGu = zzac.zza(context.getApplicationContext());
            }
            zzlVar = zzGu;
        }
        return zzlVar;
    }

    public <T> zzhv<T> zza(String str, zza<T> zzaVar) {
        zzc zzcVar = new zzc();
        zzGu.zze(new zzb(str, zzaVar, zzcVar));
        return zzcVar;
    }

    public zzhv<String> zzb(final String str, final Map<String, String> map) {
        final zzc zzcVar = new zzc();
        zzGu.zze(new zzab(str, zzcVar, new zzm.zza() { // from class: com.google.android.gms.internal.zzho.2
            @Override // com.google.android.gms.internal.zzm.zza
            public void zze(zzr zzrVar) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Failed to load URL: " + str + "\n" + zzrVar.toString());
                zzcVar.zzb((zzc) null);
            }
        }) { // from class: com.google.android.gms.internal.zzho.3
            @Override // com.google.android.gms.internal.zzk
            public Map<String, String> getHeaders() throws com.google.android.gms.internal.zza {
                return map == null ? super.getHeaders() : map;
            }
        });
        return zzcVar;
    }
}
