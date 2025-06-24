package com.google.android.gms.drive.internal;

import com.google.android.gms.internal.zzrf;
import com.google.android.gms.internal.zzrg;
import com.google.android.gms.internal.zzrh;
import com.google.android.gms.internal.zzrm;
import com.google.android.gms.internal.zzrn;
import java.io.IOException;
/* loaded from: classes.dex */
public final class zzar extends zzrh<zzar> {
    public int versionCode;
    public long zzafV;
    public String zzafX;
    public long zzafY;
    public int zzafZ;

    public zzar() {
        zzpH();
    }

    public static zzar zzl(byte[] bArr) throws zzrm {
        return (zzar) zzrn.zza(new zzar(), bArr);
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof zzar) {
            zzar zzarVar = (zzar) o;
            if (this.versionCode == zzarVar.versionCode) {
                if (this.zzafX == null) {
                    if (zzarVar.zzafX != null) {
                        return false;
                    }
                } else if (!this.zzafX.equals(zzarVar.zzafX)) {
                    return false;
                }
                if (this.zzafY == zzarVar.zzafY && this.zzafV == zzarVar.zzafV && this.zzafZ == zzarVar.zzafZ) {
                    return zza(zzarVar);
                }
                return false;
            }
            return false;
        }
        return false;
    }

    public int hashCode() {
        return (((((((((this.zzafX == null ? 0 : this.zzafX.hashCode()) + ((this.versionCode + 527) * 31)) * 31) + ((int) (this.zzafY ^ (this.zzafY >>> 32)))) * 31) + ((int) (this.zzafV ^ (this.zzafV >>> 32)))) * 31) + this.zzafZ) * 31) + zzBI();
    }

    @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
    protected int zzB() {
        int zzB = super.zzB() + zzrg.zzA(1, this.versionCode) + zzrg.zzk(2, this.zzafX) + zzrg.zze(3, this.zzafY) + zzrg.zze(4, this.zzafV);
        return this.zzafZ != -1 ? zzB + zzrg.zzA(5, this.zzafZ) : zzB;
    }

    @Override // com.google.android.gms.internal.zzrh, com.google.android.gms.internal.zzrn
    public void zza(zzrg zzrgVar) throws IOException {
        zzrgVar.zzy(1, this.versionCode);
        zzrgVar.zzb(2, this.zzafX);
        zzrgVar.zzc(3, this.zzafY);
        zzrgVar.zzc(4, this.zzafV);
        if (this.zzafZ != -1) {
            zzrgVar.zzy(5, this.zzafZ);
        }
        super.zza(zzrgVar);
    }

    @Override // com.google.android.gms.internal.zzrn
    /* renamed from: zzn */
    public zzar zzb(zzrf zzrfVar) throws IOException {
        while (true) {
            int zzBr = zzrfVar.zzBr();
            switch (zzBr) {
                case 0:
                    break;
                case 8:
                    this.versionCode = zzrfVar.zzBu();
                    break;
                case 18:
                    this.zzafX = zzrfVar.readString();
                    break;
                case 24:
                    this.zzafY = zzrfVar.zzBx();
                    break;
                case 32:
                    this.zzafV = zzrfVar.zzBx();
                    break;
                case 40:
                    this.zzafZ = zzrfVar.zzBu();
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

    public zzar zzpH() {
        this.versionCode = 1;
        this.zzafX = "";
        this.zzafY = -1L;
        this.zzafV = -1L;
        this.zzafZ = -1;
        this.zzaVU = null;
        this.zzaWf = -1;
        return this;
    }
}
