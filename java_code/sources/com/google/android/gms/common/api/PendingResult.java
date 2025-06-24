package com.google.android.gms.common.api;

import com.google.android.gms.common.api.Result;
import java.util.concurrent.TimeUnit;
/* loaded from: classes.dex */
public interface PendingResult<R extends Result> {

    /* loaded from: classes.dex */
    public interface BatchCallback {
        void zzs(Status status);
    }

    void addBatchCallback(BatchCallback batchCallback);

    R await();

    R await(long j, TimeUnit timeUnit);

    void cancel();

    boolean isCanceled();

    void setResultCallback(ResultCallback<R> resultCallback);

    void setResultCallback(ResultCallback<R> resultCallback, long j, TimeUnit timeUnit);
}
