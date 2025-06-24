package com.google.android.gms.internal;

import android.graphics.drawable.Drawable;
/* loaded from: classes.dex */
public final class zzkj extends zzku<zza, Drawable> {

    /* loaded from: classes.dex */
    public static final class zza {
        public final int zzZL;
        public final int zzZM;

        public zza(int i, int i2) {
            this.zzZL = i;
            this.zzZM = i2;
        }

        public boolean equals(Object obj) {
            if (obj instanceof zza) {
                if (this != obj) {
                    zza zzaVar = (zza) obj;
                    return zzaVar.zzZL == this.zzZL && zzaVar.zzZM == this.zzZM;
                }
                return true;
            }
            return false;
        }

        public int hashCode() {
            return com.google.android.gms.common.internal.zzt.hashCode(Integer.valueOf(this.zzZL), Integer.valueOf(this.zzZM));
        }
    }

    public zzkj() {
        super(10);
    }
}
