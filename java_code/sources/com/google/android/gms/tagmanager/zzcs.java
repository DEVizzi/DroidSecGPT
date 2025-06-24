package com.google.android.gms.tagmanager;
/* loaded from: classes.dex */
class zzcs implements zzcd {
    private final long zzMf;
    private final int zzMg;
    private double zzMh;
    private final Object zzMj;
    private long zzaNC;

    public zzcs() {
        this(60, 2000L);
    }

    public zzcs(int i, long j) {
        this.zzMj = new Object();
        this.zzMg = i;
        this.zzMh = this.zzMg;
        this.zzMf = j;
    }

    @Override // com.google.android.gms.tagmanager.zzcd
    public boolean zzkb() {
        boolean z;
        synchronized (this.zzMj) {
            long currentTimeMillis = System.currentTimeMillis();
            if (this.zzMh < this.zzMg) {
                double d = (currentTimeMillis - this.zzaNC) / this.zzMf;
                if (d > 0.0d) {
                    this.zzMh = Math.min(this.zzMg, d + this.zzMh);
                }
            }
            this.zzaNC = currentTimeMillis;
            if (this.zzMh >= 1.0d) {
                this.zzMh -= 1.0d;
                z = true;
            } else {
                zzbg.zzaC("No more tokens available.");
                z = false;
            }
        }
        return z;
    }
}
