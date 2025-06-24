package com.google.android.gms.common.api;

import android.os.Looper;
import com.google.android.gms.common.internal.zzu;
/* loaded from: classes.dex */
public final class PendingResults {

    /* loaded from: classes.dex */
    private static final class zza<R extends Result> extends AbstractPendingResult<R> {
        private final R zzXN;

        public zza(R r) {
            super(Looper.getMainLooper());
            this.zzXN = r;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.AbstractPendingResult
        public R createFailedResult(Status status) {
            if (status.getStatusCode() != this.zzXN.getStatus().getStatusCode()) {
                throw new UnsupportedOperationException("Creating failed results is not supported");
            }
            return this.zzXN;
        }
    }

    /* loaded from: classes.dex */
    private static final class zzb<R extends Result> extends AbstractPendingResult<R> {
        public zzb() {
            super(Looper.getMainLooper());
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.AbstractPendingResult
        public R createFailedResult(Status status) {
            throw new UnsupportedOperationException("Creating failed results is not supported");
        }
    }

    private PendingResults() {
    }

    public static PendingResult<Status> canceledPendingResult() {
        zzl zzlVar = new zzl(Looper.getMainLooper());
        zzlVar.cancel();
        return zzlVar;
    }

    public static <R extends Result> PendingResult<R> canceledPendingResult(R result) {
        zzu.zzb(result, "Result must not be null");
        zzu.zzb(result.getStatus().getStatusCode() == 16, "Status code must be CommonStatusCodes.CANCELED");
        zza zzaVar = new zza(result);
        zzaVar.cancel();
        return zzaVar;
    }

    public static <R extends Result> PendingResult<R> immediatePendingResult(R result) {
        zzu.zzb(result, "Result must not be null");
        zzb zzbVar = new zzb();
        zzbVar.setResult(result);
        return zzbVar;
    }

    public static PendingResult<Status> immediatePendingResult(Status result) {
        zzu.zzb(result, "Result must not be null");
        zzl zzlVar = new zzl(Looper.getMainLooper());
        zzlVar.setResult(result);
        return zzlVar;
    }
}
