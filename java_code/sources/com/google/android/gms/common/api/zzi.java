package com.google.android.gms.common.api;

import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import com.google.android.gms.common.internal.zzu;
/* loaded from: classes.dex */
public final class zzi<L> {
    private volatile L mListener;
    private final zzi<L>.zza zzXL;

    /* loaded from: classes.dex */
    private final class zza extends Handler {
        public zza(Looper looper) {
            super(looper);
        }

        @Override // android.os.Handler
        public void handleMessage(Message msg) {
            zzu.zzV(msg.what == 1);
            zzi.this.zzb((zzb) msg.obj);
        }
    }

    /* loaded from: classes.dex */
    public interface zzb<L> {
        void zzmw();

        void zzn(L l);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzi(Looper looper, L l) {
        this.zzXL = new zza(looper);
        this.mListener = (L) zzu.zzb(l, "Listener must not be null");
    }

    public void clear() {
        this.mListener = null;
    }

    public void zza(zzb<? super L> zzbVar) {
        zzu.zzb(zzbVar, "Notifier must not be null");
        this.zzXL.sendMessage(this.zzXL.obtainMessage(1, zzbVar));
    }

    void zzb(zzb<? super L> zzbVar) {
        Object obj = (L) this.mListener;
        if (obj == null) {
            zzbVar.zzmw();
            return;
        }
        try {
            zzbVar.zzn(obj);
        } catch (RuntimeException e) {
            zzbVar.zzmw();
            throw e;
        }
    }
}
