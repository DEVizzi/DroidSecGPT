package com.google.android.gms.ads.internal;

import android.content.Context;
import android.view.MotionEvent;
import com.google.android.gms.internal.zzaj;
import com.google.android.gms.internal.zzam;
import com.google.android.gms.internal.zzbz;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzhk;
import java.util.List;
import java.util.Vector;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
/* JADX INFO: Access modifiers changed from: package-private */
@zzgd
/* loaded from: classes.dex */
public class zzg implements zzaj, Runnable {
    private final List<Object[]> zzoB = new Vector();
    private final AtomicReference<zzaj> zzoC = new AtomicReference<>();
    CountDownLatch zzoD = new CountDownLatch(1);
    private zzp zzon;

    public zzg(zzp zzpVar) {
        this.zzon = zzpVar;
        if (com.google.android.gms.ads.internal.client.zzk.zzcA().zzgw()) {
            zzhk.zza(this);
        } else {
            run();
        }
    }

    private void zzbf() {
        if (this.zzoB.isEmpty()) {
            return;
        }
        for (Object[] objArr : this.zzoB) {
            if (objArr.length == 1) {
                this.zzoC.get().zza((MotionEvent) objArr[0]);
            } else if (objArr.length == 3) {
                this.zzoC.get().zza(((Integer) objArr[0]).intValue(), ((Integer) objArr[1]).intValue(), ((Integer) objArr[2]).intValue());
            }
        }
        this.zzoB.clear();
    }

    private Context zzp(Context context) {
        Context applicationContext;
        return (zzbz.zztM.get().booleanValue() && (applicationContext = context.getApplicationContext()) != null) ? applicationContext : context;
    }

    @Override // java.lang.Runnable
    public void run() {
        try {
            zza(zzb(this.zzon.zzpJ.zzGG, zzp(this.zzon.zzpH), !zzbz.zztU.get().booleanValue() || this.zzon.zzpJ.zzGJ));
        } finally {
            this.zzoD.countDown();
            this.zzon = null;
        }
    }

    @Override // com.google.android.gms.internal.zzaj
    public String zza(Context context, String str) {
        zzaj zzajVar;
        if (!zzbe() || (zzajVar = this.zzoC.get()) == null) {
            return "";
        }
        zzbf();
        return zzajVar.zza(zzp(context), str);
    }

    @Override // com.google.android.gms.internal.zzaj
    public void zza(int i, int i2, int i3) {
        zzaj zzajVar = this.zzoC.get();
        if (zzajVar == null) {
            this.zzoB.add(new Object[]{Integer.valueOf(i), Integer.valueOf(i2), Integer.valueOf(i3)});
            return;
        }
        zzbf();
        zzajVar.zza(i, i2, i3);
    }

    @Override // com.google.android.gms.internal.zzaj
    public void zza(MotionEvent motionEvent) {
        zzaj zzajVar = this.zzoC.get();
        if (zzajVar == null) {
            this.zzoB.add(new Object[]{motionEvent});
            return;
        }
        zzbf();
        zzajVar.zza(motionEvent);
    }

    protected void zza(zzaj zzajVar) {
        this.zzoC.set(zzajVar);
    }

    protected zzaj zzb(String str, Context context, boolean z) {
        return zzam.zza(str, context, z);
    }

    @Override // com.google.android.gms.internal.zzaj
    public String zzb(Context context) {
        zzaj zzajVar;
        if (!zzbe() || (zzajVar = this.zzoC.get()) == null) {
            return "";
        }
        zzbf();
        return zzajVar.zzb(zzp(context));
    }

    protected boolean zzbe() {
        try {
            this.zzoD.await();
            return true;
        } catch (InterruptedException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Interrupted during GADSignals creation.", e);
            return false;
        }
    }
}
