package com.google.android.gms.analytics.internal;

import com.google.android.gms.analytics.internal.zzq;
/* loaded from: classes.dex */
public class zzak extends zzq<zzal> {

    /* loaded from: classes.dex */
    private static class zza extends zzc implements zzq.zza<zzal> {
        private final zzal zzMD;

        public zza(zzf zzfVar) {
            super(zzfVar);
            this.zzMD = new zzal();
        }

        @Override // com.google.android.gms.analytics.internal.zzq.zza
        public void zzc(String str, boolean z) {
            if ("ga_autoActivityTracking".equals(str)) {
                this.zzMD.zzMG = z ? 1 : 0;
            } else if ("ga_anonymizeIp".equals(str)) {
                this.zzMD.zzMH = z ? 1 : 0;
            } else if (!"ga_reportUncaughtExceptions".equals(str)) {
                zzd("bool configuration name not recognized", str);
            } else {
                this.zzMD.zzMI = z ? 1 : 0;
            }
        }

        @Override // com.google.android.gms.analytics.internal.zzq.zza
        public void zzd(String str, int i) {
            if ("ga_sessionTimeout".equals(str)) {
                this.zzMD.zzMF = i;
            } else {
                zzd("int configuration name not recognized", str);
            }
        }

        @Override // com.google.android.gms.analytics.internal.zzq.zza
        public void zzk(String str, String str2) {
            this.zzMD.zzMJ.put(str, str2);
        }

        @Override // com.google.android.gms.analytics.internal.zzq.zza
        /* renamed from: zzkx */
        public zzal zziV() {
            return this.zzMD;
        }

        @Override // com.google.android.gms.analytics.internal.zzq.zza
        public void zzl(String str, String str2) {
            if ("ga_trackingId".equals(str)) {
                this.zzMD.zztd = str2;
            } else if (!"ga_sampleFrequency".equals(str)) {
                zzd("string configuration name not recognized", str);
            } else {
                try {
                    this.zzMD.zzME = Double.parseDouble(str2);
                } catch (NumberFormatException e) {
                    zzc("Error parsing ga_sampleFrequency value", str2, e);
                }
            }
        }
    }

    public zzak(zzf zzfVar) {
        super(zzfVar, new zza(zzfVar));
    }
}
