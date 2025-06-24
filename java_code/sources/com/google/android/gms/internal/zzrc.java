package com.google.android.gms.internal;

import java.io.IOException;
import java.util.Arrays;
/* loaded from: classes.dex */
public final class zzrc extends zzrh<zzrc> {
    public zza[] zzaVl;

    /* loaded from: classes.dex */
    public static final class zza extends zzrh<zza> {
        private static volatile zza[] zzaVm;
        public String name;
        public C0163zza zzaVn;

        /* renamed from: com.google.android.gms.internal.zzrc$zza$zza  reason: collision with other inner class name */
        /* loaded from: classes.dex */
        public static final class C0163zza extends zzrh<C0163zza> {
            private static volatile C0163zza[] zzaVo;
            public int type;
            public C0164zza zzaVp;

            /* renamed from: com.google.android.gms.internal.zzrc$zza$zza$zza  reason: collision with other inner class name */
            /* loaded from: classes.dex */
            public static final class C0164zza extends zzrh<C0164zza> {
                public String[] zzaVA;
                public long[] zzaVB;
                public float[] zzaVC;
                public long zzaVD;
                public byte[] zzaVq;
                public String zzaVr;
                public double zzaVs;
                public float zzaVt;
                public long zzaVu;
                public int zzaVv;
                public int zzaVw;
                public boolean zzaVx;
                public zza[] zzaVy;
                public C0163zza[] zzaVz;

                public C0164zza() {
                    zzBp();
                }

                public boolean equals(Object o) {
                    if (o == this) {
                        return true;
                    }
                    if (o instanceof C0164zza) {
                        C0164zza c0164zza = (C0164zza) o;
                        if (Arrays.equals(this.zzaVq, c0164zza.zzaVq)) {
                            if (this.zzaVr == null) {
                                if (c0164zza.zzaVr != null) {
                                    return false;
                                }
                            } else if (!this.zzaVr.equals(c0164zza.zzaVr)) {
                                return false;
                            }
                            if (Double.doubleToLongBits(this.zzaVs) == Double.doubleToLongBits(c0164zza.zzaVs) && Float.floatToIntBits(this.zzaVt) == Float.floatToIntBits(c0164zza.zzaVt) && this.zzaVu == c0164zza.zzaVu && this.zzaVv == c0164zza.zzaVv && this.zzaVw == c0164zza.zzaVw && this.zzaVx == c0164zza.zzaVx && zzrl.equals(this.zzaVy, c0164zza.zzaVy) && zzrl.equals(this.zzaVz, c0164zza.zzaVz) && zzrl.equals(this.zzaVA, c0164zza.zzaVA) && zzrl.equals(this.zzaVB, c0164zza.zzaVB) && zzrl.equals(this.zzaVC, c0164zza.zzaVC) && this.zzaVD == c0164zza.zzaVD) {
                                return zza(c0164zza);
                            }
                            return false;
                        }
                        return false;
                    }
                    return false;
                }

                public int hashCode() {
                    int hashCode = (Arrays.hashCode(this.zzaVq) + 527) * 31;
                    int hashCode2 = this.zzaVr == null ? 0 : this.zzaVr.hashCode();
                    long doubleToLongBits = Double.doubleToLongBits(this.zzaVs);
                    return (((((((((((((((this.zzaVx ? 1231 : 1237) + ((((((((((((hashCode2 + hashCode) * 31) + ((int) (doubleToLongBits ^ (doubleToLongBits >>> 32)))) * 31) + Float.floatToIntBits(this.zzaVt)) * 31) + ((int) (this.zzaVu ^ (this.zzaVu >>> 32)))) * 31) + this.zzaVv) * 31) + this.zzaVw) * 31)) * 31) + zzrl.hashCode(this.zzaVy)) * 31) + zzrl.hashCode(this.zzaVz)) * 31) + zzrl.hashCode(this.zzaVA)) * 31) + zzrl.hashCode(this.zzaVB)) * 31) + zzrl.hashCode(this.zzaVC)) * 31) + ((int) (this.zzaVD ^ (this.zzaVD >>> 32)))) * 31) + zzBI();
                }

                /* JADX INFO: Access modifiers changed from: protected */
                @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
                public int zzB() {
                    int zzB = super.zzB();
                    if (!Arrays.equals(this.zzaVq, zzrq.zzaWo)) {
                        zzB += zzrg.zzb(1, this.zzaVq);
                    }
                    if (!this.zzaVr.equals("")) {
                        zzB += zzrg.zzk(2, this.zzaVr);
                    }
                    if (Double.doubleToLongBits(this.zzaVs) != Double.doubleToLongBits(0.0d)) {
                        zzB += zzrg.zzb(3, this.zzaVs);
                    }
                    if (Float.floatToIntBits(this.zzaVt) != Float.floatToIntBits(0.0f)) {
                        zzB += zzrg.zzc(4, this.zzaVt);
                    }
                    if (this.zzaVu != 0) {
                        zzB += zzrg.zzd(5, this.zzaVu);
                    }
                    if (this.zzaVv != 0) {
                        zzB += zzrg.zzA(6, this.zzaVv);
                    }
                    if (this.zzaVw != 0) {
                        zzB += zzrg.zzB(7, this.zzaVw);
                    }
                    if (this.zzaVx) {
                        zzB += zzrg.zzc(8, this.zzaVx);
                    }
                    if (this.zzaVy != null && this.zzaVy.length > 0) {
                        int i = zzB;
                        for (int i2 = 0; i2 < this.zzaVy.length; i2++) {
                            zza zzaVar = this.zzaVy[i2];
                            if (zzaVar != null) {
                                i += zzrg.zzc(9, zzaVar);
                            }
                        }
                        zzB = i;
                    }
                    if (this.zzaVz != null && this.zzaVz.length > 0) {
                        int i3 = zzB;
                        for (int i4 = 0; i4 < this.zzaVz.length; i4++) {
                            C0163zza c0163zza = this.zzaVz[i4];
                            if (c0163zza != null) {
                                i3 += zzrg.zzc(10, c0163zza);
                            }
                        }
                        zzB = i3;
                    }
                    if (this.zzaVA != null && this.zzaVA.length > 0) {
                        int i5 = 0;
                        int i6 = 0;
                        for (int i7 = 0; i7 < this.zzaVA.length; i7++) {
                            String str = this.zzaVA[i7];
                            if (str != null) {
                                i6++;
                                i5 += zzrg.zzfj(str);
                            }
                        }
                        zzB = zzB + i5 + (i6 * 1);
                    }
                    if (this.zzaVB != null && this.zzaVB.length > 0) {
                        int i8 = 0;
                        for (int i9 = 0; i9 < this.zzaVB.length; i9++) {
                            i8 += zzrg.zzY(this.zzaVB[i9]);
                        }
                        zzB = zzB + i8 + (this.zzaVB.length * 1);
                    }
                    if (this.zzaVD != 0) {
                        zzB += zzrg.zzd(13, this.zzaVD);
                    }
                    return (this.zzaVC == null || this.zzaVC.length <= 0) ? zzB : zzB + (this.zzaVC.length * 4) + (this.zzaVC.length * 1);
                }

                public C0164zza zzBp() {
                    this.zzaVq = zzrq.zzaWo;
                    this.zzaVr = "";
                    this.zzaVs = 0.0d;
                    this.zzaVt = 0.0f;
                    this.zzaVu = 0L;
                    this.zzaVv = 0;
                    this.zzaVw = 0;
                    this.zzaVx = false;
                    this.zzaVy = zza.zzBl();
                    this.zzaVz = C0163zza.zzBn();
                    this.zzaVA = zzrq.zzaWm;
                    this.zzaVB = zzrq.zzaWi;
                    this.zzaVC = zzrq.zzaWj;
                    this.zzaVD = 0L;
                    this.zzaVU = null;
                    this.zzaWf = -1;
                    return this;
                }

                @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
                public void zza(zzrg zzrgVar) throws IOException {
                    if (!Arrays.equals(this.zzaVq, zzrq.zzaWo)) {
                        zzrgVar.zza(1, this.zzaVq);
                    }
                    if (!this.zzaVr.equals("")) {
                        zzrgVar.zzb(2, this.zzaVr);
                    }
                    if (Double.doubleToLongBits(this.zzaVs) != Double.doubleToLongBits(0.0d)) {
                        zzrgVar.zza(3, this.zzaVs);
                    }
                    if (Float.floatToIntBits(this.zzaVt) != Float.floatToIntBits(0.0f)) {
                        zzrgVar.zzb(4, this.zzaVt);
                    }
                    if (this.zzaVu != 0) {
                        zzrgVar.zzb(5, this.zzaVu);
                    }
                    if (this.zzaVv != 0) {
                        zzrgVar.zzy(6, this.zzaVv);
                    }
                    if (this.zzaVw != 0) {
                        zzrgVar.zzz(7, this.zzaVw);
                    }
                    if (this.zzaVx) {
                        zzrgVar.zzb(8, this.zzaVx);
                    }
                    if (this.zzaVy != null && this.zzaVy.length > 0) {
                        for (int i = 0; i < this.zzaVy.length; i++) {
                            zza zzaVar = this.zzaVy[i];
                            if (zzaVar != null) {
                                zzrgVar.zza(9, zzaVar);
                            }
                        }
                    }
                    if (this.zzaVz != null && this.zzaVz.length > 0) {
                        for (int i2 = 0; i2 < this.zzaVz.length; i2++) {
                            C0163zza c0163zza = this.zzaVz[i2];
                            if (c0163zza != null) {
                                zzrgVar.zza(10, c0163zza);
                            }
                        }
                    }
                    if (this.zzaVA != null && this.zzaVA.length > 0) {
                        for (int i3 = 0; i3 < this.zzaVA.length; i3++) {
                            String str = this.zzaVA[i3];
                            if (str != null) {
                                zzrgVar.zzb(11, str);
                            }
                        }
                    }
                    if (this.zzaVB != null && this.zzaVB.length > 0) {
                        for (int i4 = 0; i4 < this.zzaVB.length; i4++) {
                            zzrgVar.zzb(12, this.zzaVB[i4]);
                        }
                    }
                    if (this.zzaVD != 0) {
                        zzrgVar.zzb(13, this.zzaVD);
                    }
                    if (this.zzaVC != null && this.zzaVC.length > 0) {
                        for (int i5 = 0; i5 < this.zzaVC.length; i5++) {
                            zzrgVar.zzb(14, this.zzaVC[i5]);
                        }
                    }
                    super.zza(zzrgVar);
                }

                @Override // com.google.android.gms.internal.zzrn
                /* renamed from: zzy */
                public C0164zza zzb(zzrf zzrfVar) throws IOException {
                    while (true) {
                        int zzBr = zzrfVar.zzBr();
                        switch (zzBr) {
                            case 0:
                                break;
                            case 10:
                                this.zzaVq = zzrfVar.readBytes();
                                break;
                            case 18:
                                this.zzaVr = zzrfVar.readString();
                                break;
                            case 25:
                                this.zzaVs = zzrfVar.readDouble();
                                break;
                            case 37:
                                this.zzaVt = zzrfVar.readFloat();
                                break;
                            case 40:
                                this.zzaVu = zzrfVar.zzBt();
                                break;
                            case 48:
                                this.zzaVv = zzrfVar.zzBu();
                                break;
                            case 56:
                                this.zzaVw = zzrfVar.zzBw();
                                break;
                            case 64:
                                this.zzaVx = zzrfVar.zzBv();
                                break;
                            case 74:
                                int zzb = zzrq.zzb(zzrfVar, 74);
                                int length = this.zzaVy == null ? 0 : this.zzaVy.length;
                                zza[] zzaVarArr = new zza[zzb + length];
                                if (length != 0) {
                                    System.arraycopy(this.zzaVy, 0, zzaVarArr, 0, length);
                                }
                                while (length < zzaVarArr.length - 1) {
                                    zzaVarArr[length] = new zza();
                                    zzrfVar.zza(zzaVarArr[length]);
                                    zzrfVar.zzBr();
                                    length++;
                                }
                                zzaVarArr[length] = new zza();
                                zzrfVar.zza(zzaVarArr[length]);
                                this.zzaVy = zzaVarArr;
                                break;
                            case 82:
                                int zzb2 = zzrq.zzb(zzrfVar, 82);
                                int length2 = this.zzaVz == null ? 0 : this.zzaVz.length;
                                C0163zza[] c0163zzaArr = new C0163zza[zzb2 + length2];
                                if (length2 != 0) {
                                    System.arraycopy(this.zzaVz, 0, c0163zzaArr, 0, length2);
                                }
                                while (length2 < c0163zzaArr.length - 1) {
                                    c0163zzaArr[length2] = new C0163zza();
                                    zzrfVar.zza(c0163zzaArr[length2]);
                                    zzrfVar.zzBr();
                                    length2++;
                                }
                                c0163zzaArr[length2] = new C0163zza();
                                zzrfVar.zza(c0163zzaArr[length2]);
                                this.zzaVz = c0163zzaArr;
                                break;
                            case 90:
                                int zzb3 = zzrq.zzb(zzrfVar, 90);
                                int length3 = this.zzaVA == null ? 0 : this.zzaVA.length;
                                String[] strArr = new String[zzb3 + length3];
                                if (length3 != 0) {
                                    System.arraycopy(this.zzaVA, 0, strArr, 0, length3);
                                }
                                while (length3 < strArr.length - 1) {
                                    strArr[length3] = zzrfVar.readString();
                                    zzrfVar.zzBr();
                                    length3++;
                                }
                                strArr[length3] = zzrfVar.readString();
                                this.zzaVA = strArr;
                                break;
                            case 96:
                                int zzb4 = zzrq.zzb(zzrfVar, 96);
                                int length4 = this.zzaVB == null ? 0 : this.zzaVB.length;
                                long[] jArr = new long[zzb4 + length4];
                                if (length4 != 0) {
                                    System.arraycopy(this.zzaVB, 0, jArr, 0, length4);
                                }
                                while (length4 < jArr.length - 1) {
                                    jArr[length4] = zzrfVar.zzBt();
                                    zzrfVar.zzBr();
                                    length4++;
                                }
                                jArr[length4] = zzrfVar.zzBt();
                                this.zzaVB = jArr;
                                break;
                            case 98:
                                int zzkC = zzrfVar.zzkC(zzrfVar.zzBy());
                                int position = zzrfVar.getPosition();
                                int i = 0;
                                while (zzrfVar.zzBD() > 0) {
                                    zzrfVar.zzBt();
                                    i++;
                                }
                                zzrfVar.zzkE(position);
                                int length5 = this.zzaVB == null ? 0 : this.zzaVB.length;
                                long[] jArr2 = new long[i + length5];
                                if (length5 != 0) {
                                    System.arraycopy(this.zzaVB, 0, jArr2, 0, length5);
                                }
                                while (length5 < jArr2.length) {
                                    jArr2[length5] = zzrfVar.zzBt();
                                    length5++;
                                }
                                this.zzaVB = jArr2;
                                zzrfVar.zzkD(zzkC);
                                break;
                            case 104:
                                this.zzaVD = zzrfVar.zzBt();
                                break;
                            case 114:
                                int zzBy = zzrfVar.zzBy();
                                int zzkC2 = zzrfVar.zzkC(zzBy);
                                int i2 = zzBy / 4;
                                int length6 = this.zzaVC == null ? 0 : this.zzaVC.length;
                                float[] fArr = new float[i2 + length6];
                                if (length6 != 0) {
                                    System.arraycopy(this.zzaVC, 0, fArr, 0, length6);
                                }
                                while (length6 < fArr.length) {
                                    fArr[length6] = zzrfVar.readFloat();
                                    length6++;
                                }
                                this.zzaVC = fArr;
                                zzrfVar.zzkD(zzkC2);
                                break;
                            case 117:
                                int zzb5 = zzrq.zzb(zzrfVar, 117);
                                int length7 = this.zzaVC == null ? 0 : this.zzaVC.length;
                                float[] fArr2 = new float[zzb5 + length7];
                                if (length7 != 0) {
                                    System.arraycopy(this.zzaVC, 0, fArr2, 0, length7);
                                }
                                while (length7 < fArr2.length - 1) {
                                    fArr2[length7] = zzrfVar.readFloat();
                                    zzrfVar.zzBr();
                                    length7++;
                                }
                                fArr2[length7] = zzrfVar.readFloat();
                                this.zzaVC = fArr2;
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
            }

            public C0163zza() {
                zzBo();
            }

            public static C0163zza[] zzBn() {
                if (zzaVo == null) {
                    synchronized (zzrl.zzaWe) {
                        if (zzaVo == null) {
                            zzaVo = new C0163zza[0];
                        }
                    }
                }
                return zzaVo;
            }

            public boolean equals(Object o) {
                if (o == this) {
                    return true;
                }
                if (o instanceof C0163zza) {
                    C0163zza c0163zza = (C0163zza) o;
                    if (this.type == c0163zza.type) {
                        if (this.zzaVp == null) {
                            if (c0163zza.zzaVp != null) {
                                return false;
                            }
                        } else if (!this.zzaVp.equals(c0163zza.zzaVp)) {
                            return false;
                        }
                        return zza(c0163zza);
                    }
                    return false;
                }
                return false;
            }

            public int hashCode() {
                return (((this.zzaVp == null ? 0 : this.zzaVp.hashCode()) + ((this.type + 527) * 31)) * 31) + zzBI();
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
            public int zzB() {
                int zzB = super.zzB() + zzrg.zzA(1, this.type);
                return this.zzaVp != null ? zzB + zzrg.zzc(2, this.zzaVp) : zzB;
            }

            public C0163zza zzBo() {
                this.type = 1;
                this.zzaVp = null;
                this.zzaVU = null;
                this.zzaWf = -1;
                return this;
            }

            @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
            public void zza(zzrg zzrgVar) throws IOException {
                zzrgVar.zzy(1, this.type);
                if (this.zzaVp != null) {
                    zzrgVar.zza(2, this.zzaVp);
                }
                super.zza(zzrgVar);
            }

            @Override // com.google.android.gms.internal.zzrn
            /* renamed from: zzx */
            public C0163zza zzb(zzrf zzrfVar) throws IOException {
                while (true) {
                    int zzBr = zzrfVar.zzBr();
                    switch (zzBr) {
                        case 0:
                            break;
                        case 8:
                            int zzBu = zzrfVar.zzBu();
                            switch (zzBu) {
                                case 1:
                                case 2:
                                case 3:
                                case 4:
                                case 5:
                                case 6:
                                case 7:
                                case 8:
                                case 9:
                                case 10:
                                case 11:
                                case 12:
                                case 13:
                                case 14:
                                case 15:
                                    this.type = zzBu;
                                    continue;
                            }
                        case 18:
                            if (this.zzaVp == null) {
                                this.zzaVp = new C0164zza();
                            }
                            zzrfVar.zza(this.zzaVp);
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
        }

        public zza() {
            zzBm();
        }

        public static zza[] zzBl() {
            if (zzaVm == null) {
                synchronized (zzrl.zzaWe) {
                    if (zzaVm == null) {
                        zzaVm = new zza[0];
                    }
                }
            }
            return zzaVm;
        }

        public boolean equals(Object o) {
            if (o == this) {
                return true;
            }
            if (o instanceof zza) {
                zza zzaVar = (zza) o;
                if (this.name == null) {
                    if (zzaVar.name != null) {
                        return false;
                    }
                } else if (!this.name.equals(zzaVar.name)) {
                    return false;
                }
                if (this.zzaVn == null) {
                    if (zzaVar.zzaVn != null) {
                        return false;
                    }
                } else if (!this.zzaVn.equals(zzaVar.zzaVn)) {
                    return false;
                }
                return zza(zzaVar);
            }
            return false;
        }

        public int hashCode() {
            return (((((this.name == null ? 0 : this.name.hashCode()) + 527) * 31) + (this.zzaVn != null ? this.zzaVn.hashCode() : 0)) * 31) + zzBI();
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
        public int zzB() {
            int zzB = super.zzB() + zzrg.zzk(1, this.name);
            return this.zzaVn != null ? zzB + zzrg.zzc(2, this.zzaVn) : zzB;
        }

        public zza zzBm() {
            this.name = "";
            this.zzaVn = null;
            this.zzaVU = null;
            this.zzaWf = -1;
            return this;
        }

        @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
        public void zza(zzrg zzrgVar) throws IOException {
            zzrgVar.zzb(1, this.name);
            if (this.zzaVn != null) {
                zzrgVar.zza(2, this.zzaVn);
            }
            super.zza(zzrgVar);
        }

        @Override // com.google.android.gms.internal.zzrn
        /* renamed from: zzw */
        public zza zzb(zzrf zzrfVar) throws IOException {
            while (true) {
                int zzBr = zzrfVar.zzBr();
                switch (zzBr) {
                    case 0:
                        break;
                    case 10:
                        this.name = zzrfVar.readString();
                        break;
                    case 18:
                        if (this.zzaVn == null) {
                            this.zzaVn = new C0163zza();
                        }
                        zzrfVar.zza(this.zzaVn);
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
    }

    public zzrc() {
        zzBk();
    }

    public static zzrc zzw(byte[] bArr) throws zzrm {
        return (zzrc) zzrn.zza(new zzrc(), bArr);
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof zzrc) {
            zzrc zzrcVar = (zzrc) o;
            if (zzrl.equals(this.zzaVl, zzrcVar.zzaVl)) {
                return zza(zzrcVar);
            }
            return false;
        }
        return false;
    }

    public int hashCode() {
        return ((zzrl.hashCode(this.zzaVl) + 527) * 31) + zzBI();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
    public int zzB() {
        int zzB = super.zzB();
        if (this.zzaVl != null && this.zzaVl.length > 0) {
            for (int i = 0; i < this.zzaVl.length; i++) {
                zza zzaVar = this.zzaVl[i];
                if (zzaVar != null) {
                    zzB += zzrg.zzc(1, zzaVar);
                }
            }
        }
        return zzB;
    }

    public zzrc zzBk() {
        this.zzaVl = zza.zzBl();
        this.zzaVU = null;
        this.zzaWf = -1;
        return this;
    }

    @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
    public void zza(zzrg zzrgVar) throws IOException {
        if (this.zzaVl != null && this.zzaVl.length > 0) {
            for (int i = 0; i < this.zzaVl.length; i++) {
                zza zzaVar = this.zzaVl[i];
                if (zzaVar != null) {
                    zzrgVar.zza(1, zzaVar);
                }
            }
        }
        super.zza(zzrgVar);
    }

    @Override // com.google.android.gms.internal.zzrn
    /* renamed from: zzv */
    public zzrc zzb(zzrf zzrfVar) throws IOException {
        while (true) {
            int zzBr = zzrfVar.zzBr();
            switch (zzBr) {
                case 0:
                    break;
                case 10:
                    int zzb = zzrq.zzb(zzrfVar, 10);
                    int length = this.zzaVl == null ? 0 : this.zzaVl.length;
                    zza[] zzaVarArr = new zza[zzb + length];
                    if (length != 0) {
                        System.arraycopy(this.zzaVl, 0, zzaVarArr, 0, length);
                    }
                    while (length < zzaVarArr.length - 1) {
                        zzaVarArr[length] = new zza();
                        zzrfVar.zza(zzaVarArr[length]);
                        zzrfVar.zzBr();
                        length++;
                    }
                    zzaVarArr[length] = new zza();
                    zzrfVar.zza(zzaVarArr[length]);
                    this.zzaVl = zzaVarArr;
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
}
