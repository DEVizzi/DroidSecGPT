package com.google.android.gms.analytics.internal;

import com.google.android.gms.analytics.internal.zzq;
/* loaded from: classes.dex */
public class zzz extends zzq<zzaa> {

    /* loaded from: classes.dex */
    private static class zza implements zzq.zza<zzaa> {
        private final zzf zzJy;
        private final zzaa zzLT = new zzaa();

        public zza(zzf zzfVar) {
            this.zzJy = zzfVar;
        }

        @Override // com.google.android.gms.analytics.internal.zzq.zza
        public void zzc(String str, boolean z) {
            if (!"ga_dryRun".equals(str)) {
                this.zzJy.zzhQ().zzd("Bool xml configuration name not recognized", str);
                return;
            }
            this.zzLT.zzLY = z ? 1 : 0;
        }

        @Override // com.google.android.gms.analytics.internal.zzq.zza
        public void zzd(String str, int i) {
            if ("ga_dispatchPeriod".equals(str)) {
                this.zzLT.zzLX = i;
            } else {
                this.zzJy.zzhQ().zzd("Int xml configuration name not recognized", str);
            }
        }

        @Override // com.google.android.gms.analytics.internal.zzq.zza
        /* renamed from: zzjJ */
        public zzaa zziV() {
            return this.zzLT;
        }

        @Override // com.google.android.gms.analytics.internal.zzq.zza
        public void zzk(String str, String str2) {
        }

        @Override // com.google.android.gms.analytics.internal.zzq.zza
        public void zzl(String str, String str2) {
            if ("ga_appName".equals(str)) {
                this.zzLT.zzLU = str2;
            } else if ("ga_appVersion".equals(str)) {
                this.zzLT.zzLV = str2;
            } else if ("ga_logLevel".equals(str)) {
                this.zzLT.zzLW = str2;
            } else {
                this.zzJy.zzhQ().zzd("String xml configuration name not recognized", str);
            }
        }
    }

    public zzz(zzf zzfVar) {
        super(zzfVar, new zza(zzfVar));
    }
}
