package com.google.android.gms.analytics.internal;
/* loaded from: classes.dex */
public class zzad {
    private final long zzMf;
    private final int zzMg;
    private double zzMh;
    private long zzMi;
    private final Object zzMj;
    private final String zzuO;

    public zzad(int i, long j, String str) {
        this.zzMj = new Object();
        this.zzMg = i;
        this.zzMh = this.zzMg;
        this.zzMf = j;
        this.zzuO = str;
    }

    public zzad(String str) {
        this(60, 2000L, str);
    }

    public boolean zzkb() {
        boolean z;
        synchronized (this.zzMj) {
            long currentTimeMillis = System.currentTimeMillis();
            if (this.zzMh < this.zzMg) {
                double d = (currentTimeMillis - this.zzMi) / this.zzMf;
                if (d > 0.0d) {
                    this.zzMh = Math.min(this.zzMg, d + this.zzMh);
                }
            }
            this.zzMi = currentTimeMillis;
            if (this.zzMh >= 1.0d) {
                this.zzMh -= 1.0d;
                z = true;
            } else {
                zzae.zzaC("Excessive " + this.zzuO + " detected; call ignored.");
                z = false;
            }
        }
        return z;
    }
}
