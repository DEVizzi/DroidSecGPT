package com.google.android.gms.analytics.internal;

import android.os.Handler;
import android.os.Looper;
/* loaded from: classes.dex */
abstract class zzt {
    private static volatile Handler zzKS;
    private final zzf zzJy;
    private volatile long zzKT;
    private boolean zzKU;
    private final Runnable zzx;

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzt(zzf zzfVar) {
        com.google.android.gms.common.internal.zzu.zzu(zzfVar);
        this.zzJy = zzfVar;
        this.zzx = new Runnable() { // from class: com.google.android.gms.analytics.internal.zzt.1
            @Override // java.lang.Runnable
            public void run() {
                if (Looper.myLooper() == Looper.getMainLooper()) {
                    zzt.this.zzJy.zzhS().zze(this);
                    return;
                }
                boolean zzbp = zzt.this.zzbp();
                zzt.this.zzKT = 0L;
                if (!zzbp || zzt.this.zzKU) {
                    return;
                }
                zzt.this.run();
            }
        };
    }

    private Handler getHandler() {
        Handler handler;
        if (zzKS != null) {
            return zzKS;
        }
        synchronized (zzt.class) {
            if (zzKS == null) {
                zzKS = new Handler(this.zzJy.getContext().getMainLooper());
            }
            handler = zzKS;
        }
        return handler;
    }

    public void cancel() {
        this.zzKT = 0L;
        getHandler().removeCallbacks(this.zzx);
    }

    public abstract void run();

    public boolean zzbp() {
        return this.zzKT != 0;
    }

    public long zzjD() {
        if (this.zzKT == 0) {
            return 0L;
        }
        return Math.abs(this.zzJy.zzhP().currentTimeMillis() - this.zzKT);
    }

    public void zzt(long j) {
        cancel();
        if (j >= 0) {
            this.zzKT = this.zzJy.zzhP().currentTimeMillis();
            if (getHandler().postDelayed(this.zzx, j)) {
                return;
            }
            this.zzJy.zzhQ().zze("Failed to schedule delayed post. time", Long.valueOf(j));
        }
    }

    public void zzu(long j) {
        if (zzbp()) {
            if (j < 0) {
                cancel();
                return;
            }
            long abs = j - Math.abs(this.zzJy.zzhP().currentTimeMillis() - this.zzKT);
            long j2 = abs >= 0 ? abs : 0L;
            getHandler().removeCallbacks(this.zzx);
            if (getHandler().postDelayed(this.zzx, j2)) {
                return;
            }
            this.zzJy.zzhQ().zze("Failed to adjust delayed post. time", Long.valueOf(j2));
        }
    }
}
