package com.google.android.gms.internal;

import java.io.IOException;
/* loaded from: classes.dex */
public interface zznj {

    /* loaded from: classes.dex */
    public static final class zza extends zzrh<zza> {
        public C0140zza[] zzawk;

        /* renamed from: com.google.android.gms.internal.zznj$zza$zza  reason: collision with other inner class name */
        /* loaded from: classes.dex */
        public static final class C0140zza extends zzrh<C0140zza> {
            private static volatile C0140zza[] zzawl;
            public int viewId;
            public String zzawm;
            public String zzawn;

            public C0140zza() {
                zztW();
            }

            public static C0140zza[] zztV() {
                if (zzawl == null) {
                    synchronized (zzrl.zzaWe) {
                        if (zzawl == null) {
                            zzawl = new C0140zza[0];
                        }
                    }
                }
                return zzawl;
            }

            public boolean equals(Object o) {
                if (o == this) {
                    return true;
                }
                if (o instanceof C0140zza) {
                    C0140zza c0140zza = (C0140zza) o;
                    if (this.zzawm == null) {
                        if (c0140zza.zzawm != null) {
                            return false;
                        }
                    } else if (!this.zzawm.equals(c0140zza.zzawm)) {
                        return false;
                    }
                    if (this.zzawn == null) {
                        if (c0140zza.zzawn != null) {
                            return false;
                        }
                    } else if (!this.zzawn.equals(c0140zza.zzawn)) {
                        return false;
                    }
                    if (this.viewId == c0140zza.viewId) {
                        return zza(c0140zza);
                    }
                    return false;
                }
                return false;
            }

            public int hashCode() {
                return (((((((this.zzawm == null ? 0 : this.zzawm.hashCode()) + 527) * 31) + (this.zzawn != null ? this.zzawn.hashCode() : 0)) * 31) + this.viewId) * 31) + zzBI();
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
            public int zzB() {
                int zzB = super.zzB();
                if (!this.zzawm.equals("")) {
                    zzB += zzrg.zzk(1, this.zzawm);
                }
                if (!this.zzawn.equals("")) {
                    zzB += zzrg.zzk(2, this.zzawn);
                }
                return this.viewId != 0 ? zzB + zzrg.zzA(3, this.viewId) : zzB;
            }

            @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
            public void zza(zzrg zzrgVar) throws IOException {
                if (!this.zzawm.equals("")) {
                    zzrgVar.zzb(1, this.zzawm);
                }
                if (!this.zzawn.equals("")) {
                    zzrgVar.zzb(2, this.zzawn);
                }
                if (this.viewId != 0) {
                    zzrgVar.zzy(3, this.viewId);
                }
                super.zza(zzrgVar);
            }

            @Override // com.google.android.gms.internal.zzrn
            /* renamed from: zzq */
            public C0140zza zzb(zzrf zzrfVar) throws IOException {
                while (true) {
                    int zzBr = zzrfVar.zzBr();
                    switch (zzBr) {
                        case 0:
                            break;
                        case 10:
                            this.zzawm = zzrfVar.readString();
                            break;
                        case 18:
                            this.zzawn = zzrfVar.readString();
                            break;
                        case 24:
                            this.viewId = zzrfVar.zzBu();
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

            public C0140zza zztW() {
                this.zzawm = "";
                this.zzawn = "";
                this.viewId = 0;
                this.zzaVU = null;
                this.zzaWf = -1;
                return this;
            }
        }

        public zza() {
            zztU();
        }

        public boolean equals(Object o) {
            if (o == this) {
                return true;
            }
            if (o instanceof zza) {
                zza zzaVar = (zza) o;
                if (zzrl.equals(this.zzawk, zzaVar.zzawk)) {
                    return zza(zzaVar);
                }
                return false;
            }
            return false;
        }

        public int hashCode() {
            return ((zzrl.hashCode(this.zzawk) + 527) * 31) + zzBI();
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
        public int zzB() {
            int zzB = super.zzB();
            if (this.zzawk != null && this.zzawk.length > 0) {
                for (int i = 0; i < this.zzawk.length; i++) {
                    C0140zza c0140zza = this.zzawk[i];
                    if (c0140zza != null) {
                        zzB += zzrg.zzc(1, c0140zza);
                    }
                }
            }
            return zzB;
        }

        @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
        public void zza(zzrg zzrgVar) throws IOException {
            if (this.zzawk != null && this.zzawk.length > 0) {
                for (int i = 0; i < this.zzawk.length; i++) {
                    C0140zza c0140zza = this.zzawk[i];
                    if (c0140zza != null) {
                        zzrgVar.zza(1, c0140zza);
                    }
                }
            }
            super.zza(zzrgVar);
        }

        @Override // com.google.android.gms.internal.zzrn
        /* renamed from: zzp */
        public zza zzb(zzrf zzrfVar) throws IOException {
            while (true) {
                int zzBr = zzrfVar.zzBr();
                switch (zzBr) {
                    case 0:
                        break;
                    case 10:
                        int zzb = zzrq.zzb(zzrfVar, 10);
                        int length = this.zzawk == null ? 0 : this.zzawk.length;
                        C0140zza[] c0140zzaArr = new C0140zza[zzb + length];
                        if (length != 0) {
                            System.arraycopy(this.zzawk, 0, c0140zzaArr, 0, length);
                        }
                        while (length < c0140zzaArr.length - 1) {
                            c0140zzaArr[length] = new C0140zza();
                            zzrfVar.zza(c0140zzaArr[length]);
                            zzrfVar.zzBr();
                            length++;
                        }
                        c0140zzaArr[length] = new C0140zza();
                        zzrfVar.zza(c0140zzaArr[length]);
                        this.zzawk = c0140zzaArr;
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

        public zza zztU() {
            this.zzawk = C0140zza.zztV();
            this.zzaVU = null;
            this.zzaWf = -1;
            return this;
        }
    }

    /* loaded from: classes.dex */
    public static final class zzb extends zzrh<zzb> {
        private static volatile zzb[] zzawo;
        public String name;
        public zzd zzawp;

        public zzb() {
            zztY();
        }

        public static zzb[] zztX() {
            if (zzawo == null) {
                synchronized (zzrl.zzaWe) {
                    if (zzawo == null) {
                        zzawo = new zzb[0];
                    }
                }
            }
            return zzawo;
        }

        public boolean equals(Object o) {
            if (o == this) {
                return true;
            }
            if (o instanceof zzb) {
                zzb zzbVar = (zzb) o;
                if (this.name == null) {
                    if (zzbVar.name != null) {
                        return false;
                    }
                } else if (!this.name.equals(zzbVar.name)) {
                    return false;
                }
                if (this.zzawp == null) {
                    if (zzbVar.zzawp != null) {
                        return false;
                    }
                } else if (!this.zzawp.equals(zzbVar.zzawp)) {
                    return false;
                }
                return zza(zzbVar);
            }
            return false;
        }

        public int hashCode() {
            return (((((this.name == null ? 0 : this.name.hashCode()) + 527) * 31) + (this.zzawp != null ? this.zzawp.hashCode() : 0)) * 31) + zzBI();
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
        public int zzB() {
            int zzB = super.zzB();
            if (!this.name.equals("")) {
                zzB += zzrg.zzk(1, this.name);
            }
            return this.zzawp != null ? zzB + zzrg.zzc(2, this.zzawp) : zzB;
        }

        @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
        public void zza(zzrg zzrgVar) throws IOException {
            if (!this.name.equals("")) {
                zzrgVar.zzb(1, this.name);
            }
            if (this.zzawp != null) {
                zzrgVar.zza(2, this.zzawp);
            }
            super.zza(zzrgVar);
        }

        @Override // com.google.android.gms.internal.zzrn
        /* renamed from: zzr */
        public zzb zzb(zzrf zzrfVar) throws IOException {
            while (true) {
                int zzBr = zzrfVar.zzBr();
                switch (zzBr) {
                    case 0:
                        break;
                    case 10:
                        this.name = zzrfVar.readString();
                        break;
                    case 18:
                        if (this.zzawp == null) {
                            this.zzawp = new zzd();
                        }
                        zzrfVar.zza(this.zzawp);
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

        public zzb zztY() {
            this.name = "";
            this.zzawp = null;
            this.zzaVU = null;
            this.zzaWf = -1;
            return this;
        }
    }

    /* loaded from: classes.dex */
    public static final class zzc extends zzrh<zzc> {
        public String type;
        public zzb[] zzawq;

        public zzc() {
            zztZ();
        }

        public boolean equals(Object o) {
            if (o == this) {
                return true;
            }
            if (o instanceof zzc) {
                zzc zzcVar = (zzc) o;
                if (this.type == null) {
                    if (zzcVar.type != null) {
                        return false;
                    }
                } else if (!this.type.equals(zzcVar.type)) {
                    return false;
                }
                if (zzrl.equals(this.zzawq, zzcVar.zzawq)) {
                    return zza(zzcVar);
                }
                return false;
            }
            return false;
        }

        public int hashCode() {
            return (((((this.type == null ? 0 : this.type.hashCode()) + 527) * 31) + zzrl.hashCode(this.zzawq)) * 31) + zzBI();
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
        public int zzB() {
            int zzB = super.zzB();
            if (!this.type.equals("")) {
                zzB += zzrg.zzk(1, this.type);
            }
            if (this.zzawq == null || this.zzawq.length <= 0) {
                return zzB;
            }
            int i = zzB;
            for (int i2 = 0; i2 < this.zzawq.length; i2++) {
                zzb zzbVar = this.zzawq[i2];
                if (zzbVar != null) {
                    i += zzrg.zzc(2, zzbVar);
                }
            }
            return i;
        }

        @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
        public void zza(zzrg zzrgVar) throws IOException {
            if (!this.type.equals("")) {
                zzrgVar.zzb(1, this.type);
            }
            if (this.zzawq != null && this.zzawq.length > 0) {
                for (int i = 0; i < this.zzawq.length; i++) {
                    zzb zzbVar = this.zzawq[i];
                    if (zzbVar != null) {
                        zzrgVar.zza(2, zzbVar);
                    }
                }
            }
            super.zza(zzrgVar);
        }

        @Override // com.google.android.gms.internal.zzrn
        /* renamed from: zzs */
        public zzc zzb(zzrf zzrfVar) throws IOException {
            while (true) {
                int zzBr = zzrfVar.zzBr();
                switch (zzBr) {
                    case 0:
                        break;
                    case 10:
                        this.type = zzrfVar.readString();
                        break;
                    case 18:
                        int zzb = zzrq.zzb(zzrfVar, 18);
                        int length = this.zzawq == null ? 0 : this.zzawq.length;
                        zzb[] zzbVarArr = new zzb[zzb + length];
                        if (length != 0) {
                            System.arraycopy(this.zzawq, 0, zzbVarArr, 0, length);
                        }
                        while (length < zzbVarArr.length - 1) {
                            zzbVarArr[length] = new zzb();
                            zzrfVar.zza(zzbVarArr[length]);
                            zzrfVar.zzBr();
                            length++;
                        }
                        zzbVarArr[length] = new zzb();
                        zzrfVar.zza(zzbVarArr[length]);
                        this.zzawq = zzbVarArr;
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

        public zzc zztZ() {
            this.type = "";
            this.zzawq = zzb.zztX();
            this.zzaVU = null;
            this.zzaWf = -1;
            return this;
        }
    }

    /* loaded from: classes.dex */
    public static final class zzd extends zzrh<zzd> {
        public String zzabE;
        public boolean zzawr;
        public long zzaws;
        public double zzawt;
        public zzc zzawu;

        public zzd() {
            zzua();
        }

        public boolean equals(Object o) {
            if (o == this) {
                return true;
            }
            if (o instanceof zzd) {
                zzd zzdVar = (zzd) o;
                if (this.zzawr == zzdVar.zzawr) {
                    if (this.zzabE == null) {
                        if (zzdVar.zzabE != null) {
                            return false;
                        }
                    } else if (!this.zzabE.equals(zzdVar.zzabE)) {
                        return false;
                    }
                    if (this.zzaws == zzdVar.zzaws && Double.doubleToLongBits(this.zzawt) == Double.doubleToLongBits(zzdVar.zzawt)) {
                        if (this.zzawu == null) {
                            if (zzdVar.zzawu != null) {
                                return false;
                            }
                        } else if (!this.zzawu.equals(zzdVar.zzawu)) {
                            return false;
                        }
                        return zza(zzdVar);
                    }
                    return false;
                }
                return false;
            }
            return false;
        }

        public int hashCode() {
            int hashCode = (((this.zzabE == null ? 0 : this.zzabE.hashCode()) + (((this.zzawr ? 1231 : 1237) + 527) * 31)) * 31) + ((int) (this.zzaws ^ (this.zzaws >>> 32)));
            long doubleToLongBits = Double.doubleToLongBits(this.zzawt);
            return (((((hashCode * 31) + ((int) (doubleToLongBits ^ (doubleToLongBits >>> 32)))) * 31) + (this.zzawu != null ? this.zzawu.hashCode() : 0)) * 31) + zzBI();
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
        public int zzB() {
            int zzB = super.zzB();
            if (this.zzawr) {
                zzB += zzrg.zzc(1, this.zzawr);
            }
            if (!this.zzabE.equals("")) {
                zzB += zzrg.zzk(2, this.zzabE);
            }
            if (this.zzaws != 0) {
                zzB += zzrg.zzd(3, this.zzaws);
            }
            if (Double.doubleToLongBits(this.zzawt) != Double.doubleToLongBits(0.0d)) {
                zzB += zzrg.zzb(4, this.zzawt);
            }
            return this.zzawu != null ? zzB + zzrg.zzc(5, this.zzawu) : zzB;
        }

        @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
        public void zza(zzrg zzrgVar) throws IOException {
            if (this.zzawr) {
                zzrgVar.zzb(1, this.zzawr);
            }
            if (!this.zzabE.equals("")) {
                zzrgVar.zzb(2, this.zzabE);
            }
            if (this.zzaws != 0) {
                zzrgVar.zzb(3, this.zzaws);
            }
            if (Double.doubleToLongBits(this.zzawt) != Double.doubleToLongBits(0.0d)) {
                zzrgVar.zza(4, this.zzawt);
            }
            if (this.zzawu != null) {
                zzrgVar.zza(5, this.zzawu);
            }
            super.zza(zzrgVar);
        }

        @Override // com.google.android.gms.internal.zzrn
        /* renamed from: zzt */
        public zzd zzb(zzrf zzrfVar) throws IOException {
            while (true) {
                int zzBr = zzrfVar.zzBr();
                switch (zzBr) {
                    case 0:
                        break;
                    case 8:
                        this.zzawr = zzrfVar.zzBv();
                        break;
                    case 18:
                        this.zzabE = zzrfVar.readString();
                        break;
                    case 24:
                        this.zzaws = zzrfVar.zzBt();
                        break;
                    case 33:
                        this.zzawt = zzrfVar.readDouble();
                        break;
                    case 42:
                        if (this.zzawu == null) {
                            this.zzawu = new zzc();
                        }
                        zzrfVar.zza(this.zzawu);
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

        public zzd zzua() {
            this.zzawr = false;
            this.zzabE = "";
            this.zzaws = 0L;
            this.zzawt = 0.0d;
            this.zzawu = null;
            this.zzaVU = null;
            this.zzaWf = -1;
            return this;
        }
    }
}
