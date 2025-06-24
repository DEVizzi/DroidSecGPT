package com.google.android.gms.internal;
/* loaded from: classes.dex */
public final class zzpv {
    private final boolean zzaOS;
    private final boolean zzaOT;
    private final String zzaOU;
    private final String zztd;

    /* loaded from: classes.dex */
    public static final class zza {
        private boolean zzaOS = true;
        private boolean zzaOT = false;
        private final String zzaOU;
        private String zztd;

        public zza(String str) {
            this.zzaOU = str;
        }

        public zza zzap(boolean z) {
            this.zzaOS = z;
            return this;
        }

        public zza zzaq(boolean z) {
            this.zzaOT = z;
            return this;
        }

        public zza zzeS(String str) {
            this.zztd = str;
            return this;
        }

        public zzpv zzzW() {
            return new zzpv(this);
        }
    }

    private zzpv(zza zzaVar) {
        this.zzaOU = zzaVar.zzaOU;
        this.zzaOS = zzaVar.zzaOS;
        this.zzaOT = zzaVar.zzaOT;
        this.zztd = zzaVar.zztd;
    }

    public String getTrackingId() {
        return this.zztd;
    }

    public String zzzT() {
        return this.zzaOU;
    }

    public boolean zzzU() {
        return this.zzaOS;
    }

    public boolean zzzV() {
        return this.zzaOT;
    }
}
