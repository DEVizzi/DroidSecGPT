package com.google.android.gms.internal;

import com.google.android.gms.internal.zzaf;
import java.io.IOException;
/* loaded from: classes.dex */
public interface zzpx {

    /* loaded from: classes.dex */
    public static final class zza extends zzrh<zza> {
        public long zzaOZ;
        public zzaf.zzj zzaPa;
        public zzaf.zzf zziO;

        public zza() {
            zzzY();
        }

        public static zza zzs(byte[] bArr) throws zzrm {
            return (zza) zzrn.zza(new zza(), bArr);
        }

        public boolean equals(Object o) {
            if (o == this) {
                return true;
            }
            if (o instanceof zza) {
                zza zzaVar = (zza) o;
                if (this.zzaOZ == zzaVar.zzaOZ) {
                    if (this.zziO == null) {
                        if (zzaVar.zziO != null) {
                            return false;
                        }
                    } else if (!this.zziO.equals(zzaVar.zziO)) {
                        return false;
                    }
                    if (this.zzaPa == null) {
                        if (zzaVar.zzaPa != null) {
                            return false;
                        }
                    } else if (!this.zzaPa.equals(zzaVar.zzaPa)) {
                        return false;
                    }
                    return zza(zzaVar);
                }
                return false;
            }
            return false;
        }

        public int hashCode() {
            return (((((this.zziO == null ? 0 : this.zziO.hashCode()) + ((((int) (this.zzaOZ ^ (this.zzaOZ >>> 32))) + 527) * 31)) * 31) + (this.zzaPa != null ? this.zzaPa.hashCode() : 0)) * 31) + zzBI();
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
        public int zzB() {
            int zzB = super.zzB() + zzrg.zzd(1, this.zzaOZ);
            if (this.zziO != null) {
                zzB += zzrg.zzc(2, this.zziO);
            }
            return this.zzaPa != null ? zzB + zzrg.zzc(3, this.zzaPa) : zzB;
        }

        @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
        public void zza(zzrg zzrgVar) throws IOException {
            zzrgVar.zzb(1, this.zzaOZ);
            if (this.zziO != null) {
                zzrgVar.zza(2, this.zziO);
            }
            if (this.zzaPa != null) {
                zzrgVar.zza(3, this.zzaPa);
            }
            super.zza(zzrgVar);
        }

        @Override // com.google.android.gms.internal.zzrn
        /* renamed from: zzu */
        public zza zzb(zzrf zzrfVar) throws IOException {
            while (true) {
                int zzBr = zzrfVar.zzBr();
                switch (zzBr) {
                    case 0:
                        break;
                    case 8:
                        this.zzaOZ = zzrfVar.zzBt();
                        break;
                    case 18:
                        if (this.zziO == null) {
                            this.zziO = new zzaf.zzf();
                        }
                        zzrfVar.zza(this.zziO);
                        break;
                    case 26:
                        if (this.zzaPa == null) {
                            this.zzaPa = new zzaf.zzj();
                        }
                        zzrfVar.zza(this.zzaPa);
                        break;
                    default:
                        if (!zza(zzrfVar, zzBr)) {
                            break;
                        } else {
                            break;
                        }
                }
            }
            return this;
        }

        public zza zzzY() {
            this.zzaOZ = 0L;
            this.zziO = null;
            this.zzaPa = null;
            this.zzaVU = null;
            this.zzaWf = -1;
            return this;
        }
    }
}
