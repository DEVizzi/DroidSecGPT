package com.google.android.gms.internal;

import android.app.PendingIntent;
import android.content.Context;
import android.util.Log;
import com.google.android.gms.internal.zzoz;
@Deprecated
/* loaded from: classes.dex */
public class zzoy implements zzoz.zza {
    private final zzoz zzaGB;
    private boolean zzaGC;

    public zzoy(Context context, int i) {
        this(context, i, null);
    }

    public zzoy(Context context, int i, String str) {
        this(context, i, str, null, true);
    }

    public zzoy(Context context, int i, String str, String str2, boolean z) {
        this.zzaGB = new zzoz(context, i, str, str2, this, z, context != context.getApplicationContext() ? context.getClass().getName() : "OneTimePlayLogger");
        this.zzaGC = true;
    }

    private void zzxk() {
        if (!this.zzaGC) {
            throw new IllegalStateException("Cannot reuse one-time logger after sending.");
        }
    }

    public void send() {
        zzxk();
        this.zzaGB.start();
        this.zzaGC = false;
    }

    public void zza(String str, byte[] bArr, String... strArr) {
        zzxk();
        this.zzaGB.zzb(str, bArr, strArr);
    }

    @Override // com.google.android.gms.internal.zzoz.zza
    public void zzf(PendingIntent pendingIntent) {
        Log.w("OneTimePlayLogger", "logger connection failed: " + pendingIntent);
    }

    @Override // com.google.android.gms.internal.zzoz.zza
    public void zzxl() {
        this.zzaGB.stop();
    }

    @Override // com.google.android.gms.internal.zzoz.zza
    public void zzxm() {
        Log.w("OneTimePlayLogger", "logger connection failed");
    }
}
