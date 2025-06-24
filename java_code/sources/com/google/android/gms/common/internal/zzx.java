package com.google.android.gms.common.internal;

import android.content.Context;
import android.os.IBinder;
import android.view.View;
import com.google.android.gms.common.internal.zzr;
import com.google.android.gms.dynamic.zzg;
/* loaded from: classes.dex */
public final class zzx extends com.google.android.gms.dynamic.zzg<zzr> {
    private static final zzx zzabe = new zzx();

    private zzx() {
        super("com.google.android.gms.common.ui.SignInButtonCreatorImpl");
    }

    public static View zzb(Context context, int i, int i2) throws zzg.zza {
        return zzabe.zzc(context, i, i2);
    }

    private View zzc(Context context, int i, int i2) throws zzg.zza {
        try {
            return (View) com.google.android.gms.dynamic.zze.zzn(zzak(context).zza(com.google.android.gms.dynamic.zze.zzw(context), i, i2));
        } catch (Exception e) {
            throw new zzg.zza("Could not get button with size " + i + " and color " + i2, e);
        }
    }

    @Override // com.google.android.gms.dynamic.zzg
    /* renamed from: zzaJ */
    public zzr zzd(IBinder iBinder) {
        return zzr.zza.zzaI(iBinder);
    }
}
