package com.google.android.gms.internal;

import java.io.IOException;
/* loaded from: classes.dex */
public interface zzag {

    /* loaded from: classes.dex */
    public static final class zza extends zzrh<zza> {
        private static volatile zza[] zziQ;
        public int type;
        public String zziR;
        public zza[] zziS;
        public zza[] zziT;
        public zza[] zziU;
        public String zziV;
        public String zziW;
        public long zziX;
        public boolean zziY;
        public zza[] zziZ;
        public int[] zzja;
        public boolean zzjb;

        public zza() {
            zzR();
        }

        public static zza[] zzQ() {
            if (zziQ == null) {
                synchronized (zzrl.zzaWe) {
                    if (zziQ == null) {
                        zziQ = new zza[0];
                    }
                }
            }
            return zziQ;
        }

        public boolean equals(Object o) {
            if (o == this) {
                return true;
            }
            if (o instanceof zza) {
                zza zzaVar = (zza) o;
                if (this.type == zzaVar.type) {
                    if (this.zziR == null) {
                        if (zzaVar.zziR != null) {
                            return false;
                        }
                    } else if (!this.zziR.equals(zzaVar.zziR)) {
                        return false;
                    }
                    if (zzrl.equals(this.zziS, zzaVar.zziS) && zzrl.equals(this.zziT, zzaVar.zziT) && zzrl.equals(this.zziU, zzaVar.zziU)) {
                        if (this.zziV == null) {
                            if (zzaVar.zziV != null) {
                                return false;
                            }
                        } else if (!this.zziV.equals(zzaVar.zziV)) {
                            return false;
                        }
                        if (this.zziW == null) {
                            if (zzaVar.zziW != null) {
                                return false;
                            }
                        } else if (!this.zziW.equals(zzaVar.zziW)) {
                            return false;
                        }
                        if (this.zziX == zzaVar.zziX && this.zziY == zzaVar.zziY && zzrl.equals(this.zziZ, zzaVar.zziZ) && zzrl.equals(this.zzja, zzaVar.zzja) && this.zzjb == zzaVar.zzjb) {
                            return zza(zzaVar);
                        }
                        return false;
                    }
                    return false;
                }
                return false;
            }
            return false;
        }

        public int hashCode() {
            return (((((((((this.zziY ? 1231 : 1237) + (((((((this.zziV == null ? 0 : this.zziV.hashCode()) + (((((((((this.zziR == null ? 0 : this.zziR.hashCode()) + ((this.type + 527) * 31)) * 31) + zzrl.hashCode(this.zziS)) * 31) + zzrl.hashCode(this.zziT)) * 31) + zzrl.hashCode(this.zziU)) * 31)) * 31) + (this.zziW != null ? this.zziW.hashCode() : 0)) * 31) + ((int) (this.zziX ^ (this.zziX >>> 32)))) * 31)) * 31) + zzrl.hashCode(this.zziZ)) * 31) + zzrl.hashCode(this.zzja)) * 31) + (this.zzjb ? 1231 : 1237)) * 31) + zzBI();
        }

        @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
        protected int zzB() {
            int zzB = super.zzB() + zzrg.zzA(1, this.type);
            if (!this.zziR.equals("")) {
                zzB += zzrg.zzk(2, this.zziR);
            }
            if (this.zziS != null && this.zziS.length > 0) {
                int i = zzB;
                for (int i2 = 0; i2 < this.zziS.length; i2++) {
                    zza zzaVar = this.zziS[i2];
                    if (zzaVar != null) {
                        i += zzrg.zzc(3, zzaVar);
                    }
                }
                zzB = i;
            }
            if (this.zziT != null && this.zziT.length > 0) {
                int i3 = zzB;
                for (int i4 = 0; i4 < this.zziT.length; i4++) {
                    zza zzaVar2 = this.zziT[i4];
                    if (zzaVar2 != null) {
                        i3 += zzrg.zzc(4, zzaVar2);
                    }
                }
                zzB = i3;
            }
            if (this.zziU != null && this.zziU.length > 0) {
                int i5 = zzB;
                for (int i6 = 0; i6 < this.zziU.length; i6++) {
                    zza zzaVar3 = this.zziU[i6];
                    if (zzaVar3 != null) {
                        i5 += zzrg.zzc(5, zzaVar3);
                    }
                }
                zzB = i5;
            }
            if (!this.zziV.equals("")) {
                zzB += zzrg.zzk(6, this.zziV);
            }
            if (!this.zziW.equals("")) {
                zzB += zzrg.zzk(7, this.zziW);
            }
            if (this.zziX != 0) {
                zzB += zzrg.zzd(8, this.zziX);
            }
            if (this.zzjb) {
                zzB += zzrg.zzc(9, this.zzjb);
            }
            if (this.zzja != null && this.zzja.length > 0) {
                int i7 = 0;
                for (int i8 = 0; i8 < this.zzja.length; i8++) {
                    i7 += zzrg.zzkJ(this.zzja[i8]);
                }
                zzB = zzB + i7 + (this.zzja.length * 1);
            }
            if (this.zziZ != null && this.zziZ.length > 0) {
                for (int i9 = 0; i9 < this.zziZ.length; i9++) {
                    zza zzaVar4 = this.zziZ[i9];
                    if (zzaVar4 != null) {
                        zzB += zzrg.zzc(11, zzaVar4);
                    }
                }
            }
            return this.zziY ? zzB + zzrg.zzc(12, this.zziY) : zzB;
        }

        public zza zzR() {
            this.type = 1;
            this.zziR = "";
            this.zziS = zzQ();
            this.zziT = zzQ();
            this.zziU = zzQ();
            this.zziV = "";
            this.zziW = "";
            this.zziX = 0L;
            this.zziY = false;
            this.zziZ = zzQ();
            this.zzja = zzrq.zzaWh;
            this.zzjb = false;
            this.zzaVU = null;
            this.zzaWf = -1;
            return this;
        }

        @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
        public void zza(zzrg zzrgVar) throws IOException {
            zzrgVar.zzy(1, this.type);
            if (!this.zziR.equals("")) {
                zzrgVar.zzb(2, this.zziR);
            }
            if (this.zziS != null && this.zziS.length > 0) {
                for (int i = 0; i < this.zziS.length; i++) {
                    zza zzaVar = this.zziS[i];
                    if (zzaVar != null) {
                        zzrgVar.zza(3, zzaVar);
                    }
                }
            }
            if (this.zziT != null && this.zziT.length > 0) {
                for (int i2 = 0; i2 < this.zziT.length; i2++) {
                    zza zzaVar2 = this.zziT[i2];
                    if (zzaVar2 != null) {
                        zzrgVar.zza(4, zzaVar2);
                    }
                }
            }
            if (this.zziU != null && this.zziU.length > 0) {
                for (int i3 = 0; i3 < this.zziU.length; i3++) {
                    zza zzaVar3 = this.zziU[i3];
                    if (zzaVar3 != null) {
                        zzrgVar.zza(5, zzaVar3);
                    }
                }
            }
            if (!this.zziV.equals("")) {
                zzrgVar.zzb(6, this.zziV);
            }
            if (!this.zziW.equals("")) {
                zzrgVar.zzb(7, this.zziW);
            }
            if (this.zziX != 0) {
                zzrgVar.zzb(8, this.zziX);
            }
            if (this.zzjb) {
                zzrgVar.zzb(9, this.zzjb);
            }
            if (this.zzja != null && this.zzja.length > 0) {
                for (int i4 = 0; i4 < this.zzja.length; i4++) {
                    zzrgVar.zzy(10, this.zzja[i4]);
                }
            }
            if (this.zziZ != null && this.zziZ.length > 0) {
                for (int i5 = 0; i5 < this.zziZ.length; i5++) {
                    zza zzaVar4 = this.zziZ[i5];
                    if (zzaVar4 != null) {
                        zzrgVar.zza(11, zzaVar4);
                    }
                }
            }
            if (this.zziY) {
                zzrgVar.zzb(12, this.zziY);
            }
            super.zza(zzrgVar);
        }

        @Override // com.google.android.gms.internal.zzrn
        /* renamed from: zzl */
        public zza zzb(zzrf zzrfVar) throws IOException {
            int i;
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
                                this.type = zzBu;
                                continue;
                        }
                    case 18:
                        this.zziR = zzrfVar.readString();
                        break;
                    case 26:
                        int zzb = zzrq.zzb(zzrfVar, 26);
                        int length = this.zziS == null ? 0 : this.zziS.length;
                        zza[] zzaVarArr = new zza[zzb + length];
                        if (length != 0) {
                            System.arraycopy(this.zziS, 0, zzaVarArr, 0, length);
                        }
                        while (length < zzaVarArr.length - 1) {
                            zzaVarArr[length] = new zza();
                            zzrfVar.zza(zzaVarArr[length]);
                            zzrfVar.zzBr();
                            length++;
                        }
                        zzaVarArr[length] = new zza();
                        zzrfVar.zza(zzaVarArr[length]);
                        this.zziS = zzaVarArr;
                        break;
                    case 34:
                        int zzb2 = zzrq.zzb(zzrfVar, 34);
                        int length2 = this.zziT == null ? 0 : this.zziT.length;
                        zza[] zzaVarArr2 = new zza[zzb2 + length2];
                        if (length2 != 0) {
                            System.arraycopy(this.zziT, 0, zzaVarArr2, 0, length2);
                        }
                        while (length2 < zzaVarArr2.length - 1) {
                            zzaVarArr2[length2] = new zza();
                            zzrfVar.zza(zzaVarArr2[length2]);
                            zzrfVar.zzBr();
                            length2++;
                        }
                        zzaVarArr2[length2] = new zza();
                        zzrfVar.zza(zzaVarArr2[length2]);
                        this.zziT = zzaVarArr2;
                        break;
                    case 42:
                        int zzb3 = zzrq.zzb(zzrfVar, 42);
                        int length3 = this.zziU == null ? 0 : this.zziU.length;
                        zza[] zzaVarArr3 = new zza[zzb3 + length3];
                        if (length3 != 0) {
                            System.arraycopy(this.zziU, 0, zzaVarArr3, 0, length3);
                        }
                        while (length3 < zzaVarArr3.length - 1) {
                            zzaVarArr3[length3] = new zza();
                            zzrfVar.zza(zzaVarArr3[length3]);
                            zzrfVar.zzBr();
                            length3++;
                        }
                        zzaVarArr3[length3] = new zza();
                        zzrfVar.zza(zzaVarArr3[length3]);
                        this.zziU = zzaVarArr3;
                        break;
                    case 50:
                        this.zziV = zzrfVar.readString();
                        break;
                    case 58:
                        this.zziW = zzrfVar.readString();
                        break;
                    case 64:
                        this.zziX = zzrfVar.zzBt();
                        break;
                    case 72:
                        this.zzjb = zzrfVar.zzBv();
                        break;
                    case 80:
                        int zzb4 = zzrq.zzb(zzrfVar, 80);
                        int[] iArr = new int[zzb4];
                        int i2 = 0;
                        int i3 = 0;
                        while (i2 < zzb4) {
                            if (i2 != 0) {
                                zzrfVar.zzBr();
                            }
                            int zzBu2 = zzrfVar.zzBu();
                            switch (zzBu2) {
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
                                case 16:
                                case 17:
                                    i = i3 + 1;
                                    iArr[i3] = zzBu2;
                                    break;
                                default:
                                    i = i3;
                                    break;
                            }
                            i2++;
                            i3 = i;
                        }
                        if (i3 != 0) {
                            int length4 = this.zzja == null ? 0 : this.zzja.length;
                            if (length4 != 0 || i3 != iArr.length) {
                                int[] iArr2 = new int[length4 + i3];
                                if (length4 != 0) {
                                    System.arraycopy(this.zzja, 0, iArr2, 0, length4);
                                }
                                System.arraycopy(iArr, 0, iArr2, length4, i3);
                                this.zzja = iArr2;
                                break;
                            } else {
                                this.zzja = iArr;
                                break;
                            }
                        } else {
                            break;
                        }
                    case 82:
                        int zzkC = zzrfVar.zzkC(zzrfVar.zzBy());
                        int position = zzrfVar.getPosition();
                        int i4 = 0;
                        while (zzrfVar.zzBD() > 0) {
                            switch (zzrfVar.zzBu()) {
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
                                case 16:
                                case 17:
                                    i4++;
                                    break;
                            }
                        }
                        if (i4 != 0) {
                            zzrfVar.zzkE(position);
                            int length5 = this.zzja == null ? 0 : this.zzja.length;
                            int[] iArr3 = new int[i4 + length5];
                            if (length5 != 0) {
                                System.arraycopy(this.zzja, 0, iArr3, 0, length5);
                            }
                            while (zzrfVar.zzBD() > 0) {
                                int zzBu3 = zzrfVar.zzBu();
                                switch (zzBu3) {
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
                                    case 16:
                                    case 17:
                                        iArr3[length5] = zzBu3;
                                        length5++;
                                        break;
                                }
                            }
                            this.zzja = iArr3;
                        }
                        zzrfVar.zzkD(zzkC);
                        break;
                    case 90:
                        int zzb5 = zzrq.zzb(zzrfVar, 90);
                        int length6 = this.zziZ == null ? 0 : this.zziZ.length;
                        zza[] zzaVarArr4 = new zza[zzb5 + length6];
                        if (length6 != 0) {
                            System.arraycopy(this.zziZ, 0, zzaVarArr4, 0, length6);
                        }
                        while (length6 < zzaVarArr4.length - 1) {
                            zzaVarArr4[length6] = new zza();
                            zzrfVar.zza(zzaVarArr4[length6]);
                            zzrfVar.zzBr();
                            length6++;
                        }
                        zzaVarArr4[length6] = new zza();
                        zzrfVar.zza(zzaVarArr4[length6]);
                        this.zziZ = zzaVarArr4;
                        break;
                    case 96:
                        this.zziY = zzrfVar.zzBv();
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
}
