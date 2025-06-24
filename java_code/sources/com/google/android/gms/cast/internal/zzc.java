package com.google.android.gms.cast.internal;

import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
/* loaded from: classes.dex */
public abstract class zzc extends zzd {
    protected final Handler mHandler;
    protected final long zzUe;
    protected final Runnable zzUf;
    protected boolean zzUg;

    /* loaded from: classes.dex */
    private class zza implements Runnable {
        private zza() {
        }

        @Override // java.lang.Runnable
        public void run() {
            zzc.this.zzUg = false;
            zzc.this.zzQ(zzc.this.zzz(SystemClock.elapsedRealtime()));
        }
    }

    public zzc(String str, String str2, String str3) {
        this(str, str2, str3, 1000L);
    }

    public zzc(String str, String str2, String str3, long j) {
        super(str, str2, str3);
        this.mHandler = new Handler(Looper.getMainLooper());
        this.zzUf = new zza();
        this.zzUe = j;
        zzQ(false);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void zzQ(boolean z) {
        if (this.zzUg != z) {
            this.zzUg = z;
            if (z) {
                this.mHandler.postDelayed(this.zzUf, this.zzUe);
            } else {
                this.mHandler.removeCallbacks(this.zzUf);
            }
        }
    }

    @Override // com.google.android.gms.cast.internal.zzd
    public void zzlJ() {
        zzQ(false);
    }

    protected abstract boolean zzz(long j);
}
