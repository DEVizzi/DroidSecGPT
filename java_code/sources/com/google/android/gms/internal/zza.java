package com.google.android.gms.internal;

import android.content.Intent;
/* loaded from: classes.dex */
public class zza extends zzr {
    private Intent zza;

    public zza() {
    }

    public zza(zzi zziVar) {
        super(zziVar);
    }

    @Override // java.lang.Throwable
    public String getMessage() {
        return this.zza != null ? "User needs to (re)enter credentials." : super.getMessage();
    }
}
