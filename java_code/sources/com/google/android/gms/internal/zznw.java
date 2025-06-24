package com.google.android.gms.internal;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.os.Build;
import android.text.TextUtils;
import android.util.Log;
import java.util.ArrayList;
import java.util.List;
/* loaded from: classes.dex */
public class zznw {
    private static final zza[] zzaEq = new zza[0];
    private static zznw zzaEr;
    private final Application zzaEs;
    private zzod zzaEt;
    private final List<zza> zzaEu;
    private zzog zzaEv;

    /* loaded from: classes.dex */
    public interface zza {
        void zza(zzod zzodVar);

        void zza(zzod zzodVar, Activity activity);
    }

    private zznw(Application application) {
        com.google.android.gms.common.internal.zzu.zzu(application);
        this.zzaEs = application;
        this.zzaEu = new ArrayList();
    }

    public static zznw zzaC(Context context) {
        zznw zznwVar;
        com.google.android.gms.common.internal.zzu.zzu(context);
        Application application = (Application) context.getApplicationContext();
        com.google.android.gms.common.internal.zzu.zzu(application);
        synchronized (zznw.class) {
            if (zzaEr == null) {
                zzaEr = new zznw(application);
            }
            zznwVar = zzaEr;
        }
        return zznwVar;
    }

    private zza[] zzwh() {
        zza[] zzaVarArr;
        synchronized (this.zzaEu) {
            zzaVarArr = this.zzaEu.isEmpty() ? zzaEq : (zza[]) this.zzaEu.toArray(new zza[this.zzaEu.size()]);
        }
        return zzaVarArr;
    }

    public void zza(zza zzaVar) {
        com.google.android.gms.common.internal.zzu.zzu(zzaVar);
        synchronized (this.zzaEu) {
            this.zzaEu.remove(zzaVar);
            this.zzaEu.add(zzaVar);
        }
    }

    public void zzaf(boolean z) {
        if (Build.VERSION.SDK_INT < 14) {
            Log.i("com.google.android.gms.measurement.ScreenViewService", "AutoScreeViewTracking is not supported on API 14 or earlier devices");
        } else if (zzwg() != z) {
            if (z) {
                this.zzaEv = new zzog(this);
                this.zzaEs.registerActivityLifecycleCallbacks(this.zzaEv);
                return;
            }
            this.zzaEs.unregisterActivityLifecycleCallbacks(this.zzaEv);
            this.zzaEv = null;
        }
    }

    public void zzb(zzod zzodVar, Activity activity) {
        com.google.android.gms.common.internal.zzu.zzu(zzodVar);
        zza[] zzaVarArr = null;
        if (zzodVar.isMutable()) {
            if (activity instanceof zznv) {
                ((zznv) activity).zzb(zzodVar);
            }
            if (this.zzaEt != null) {
                zzodVar.zzhL(this.zzaEt.zzbn());
                zzodVar.zzdJ(this.zzaEt.zzwB());
            }
            zza[] zzwh = zzwh();
            for (zza zzaVar : zzwh) {
                zzaVar.zza(zzodVar, activity);
            }
            zzodVar.zzwF();
            if (TextUtils.isEmpty(zzodVar.zzwB())) {
                return;
            }
            zzaVarArr = zzwh;
        }
        if (this.zzaEt != null && this.zzaEt.zzbn() == zzodVar.zzbn()) {
            this.zzaEt = zzodVar;
            return;
        }
        zzwf();
        this.zzaEt = zzodVar;
        if (zzaVarArr == null) {
            zzaVarArr = zzwh();
        }
        for (zza zzaVar2 : zzaVarArr) {
            zzaVar2.zza(zzodVar);
        }
    }

    public zzod zzwe() {
        return this.zzaEt;
    }

    public void zzwf() {
        this.zzaEt = null;
    }

    public boolean zzwg() {
        return this.zzaEv != null;
    }
}
