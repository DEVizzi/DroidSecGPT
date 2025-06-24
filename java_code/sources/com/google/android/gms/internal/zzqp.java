package com.google.android.gms.internal;

import android.content.Context;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
/* loaded from: classes.dex */
public class zzqp {
    private boolean mClosed;
    private String zzaLc;
    private final ScheduledExecutorService zzaMX;
    private ScheduledFuture<?> zzaMZ;

    public zzqp() {
        this(Executors.newSingleThreadScheduledExecutor());
    }

    public zzqp(String str) {
        this(Executors.newSingleThreadScheduledExecutor());
        this.zzaLc = str;
    }

    zzqp(ScheduledExecutorService scheduledExecutorService) {
        this.zzaMZ = null;
        this.zzaLc = null;
        this.zzaMX = scheduledExecutorService;
        this.mClosed = false;
    }

    public void zza(Context context, zzqd zzqdVar, long j, zzqn zzqnVar) {
        synchronized (this) {
            com.google.android.gms.tagmanager.zzbg.zzaB("ResourceLoaderScheduler: Loading new resource.");
            if (this.zzaMZ != null) {
                return;
            }
            this.zzaMZ = this.zzaMX.schedule(this.zzaLc != null ? new zzqo(context, zzqdVar, zzqnVar, this.zzaLc) : new zzqo(context, zzqdVar, zzqnVar), j, TimeUnit.MILLISECONDS);
        }
    }
}
