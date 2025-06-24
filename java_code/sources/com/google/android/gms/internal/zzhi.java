package com.google.android.gms.internal;

import android.os.Handler;
import android.os.Looper;
import android.os.Message;
@zzgd
/* loaded from: classes.dex */
public class zzhi extends Handler {
    public zzhi(Looper looper) {
        super(looper);
    }

    @Override // android.os.Handler
    public void handleMessage(Message msg) {
        try {
            super.handleMessage(msg);
        } catch (Exception e) {
            com.google.android.gms.ads.internal.zzo.zzby().zzc((Throwable) e, false);
            throw e;
        }
    }
}
