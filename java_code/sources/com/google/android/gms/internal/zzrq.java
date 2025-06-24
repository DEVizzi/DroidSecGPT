package com.google.android.gms.internal;

import java.io.IOException;
/* loaded from: classes.dex */
public final class zzrq {
    public static final int[] zzaWh = new int[0];
    public static final long[] zzaWi = new long[0];
    public static final float[] zzaWj = new float[0];
    public static final double[] zzaWk = new double[0];
    public static final boolean[] zzaWl = new boolean[0];
    public static final String[] zzaWm = new String[0];
    public static final byte[][] zzaWn = new byte[0];
    public static final byte[] zzaWo = new byte[0];

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int zzD(int i, int i2) {
        return (i << 3) | i2;
    }

    public static final int zzb(zzrf zzrfVar, int i) throws IOException {
        int i2 = 1;
        int position = zzrfVar.getPosition();
        zzrfVar.zzkA(i);
        while (zzrfVar.zzBr() == i) {
            zzrfVar.zzkA(i);
            i2++;
        }
        zzrfVar.zzkE(position);
        return i2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int zzkU(int i) {
        return i & 7;
    }

    public static int zzkV(int i) {
        return i >>> 3;
    }
}
