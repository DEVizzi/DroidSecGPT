package com.google.android.gms.internal;

import android.content.Context;
import android.view.View;
import com.google.android.gms.ads.internal.client.AdSizeParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.WeakHashMap;
@zzgd
/* loaded from: classes.dex */
public class zzay implements zzba {
    private final VersionInfoParcel zzoM;
    private final Object zzqt = new Object();
    private final WeakHashMap<zzha, zzaz> zzqu = new WeakHashMap<>();
    private final ArrayList<zzaz> zzqv = new ArrayList<>();
    private final Context zzqw;
    private final zzdt zzqx;

    public zzay(Context context, VersionInfoParcel versionInfoParcel, zzdt zzdtVar) {
        this.zzqw = context.getApplicationContext();
        this.zzoM = versionInfoParcel;
        this.zzqx = zzdtVar;
    }

    public zzaz zza(AdSizeParcel adSizeParcel, zzha zzhaVar) {
        return zza(adSizeParcel, zzhaVar, zzhaVar.zzzE.getWebView());
    }

    public zzaz zza(AdSizeParcel adSizeParcel, zzha zzhaVar, View view) {
        zzaz zzazVar;
        synchronized (this.zzqt) {
            if (zzf(zzhaVar)) {
                zzazVar = this.zzqu.get(zzhaVar);
            } else {
                zzazVar = new zzaz(adSizeParcel, zzhaVar, this.zzoM, view, this.zzqx);
                zzazVar.zza(this);
                this.zzqu.put(zzhaVar, zzazVar);
                this.zzqv.add(zzazVar);
            }
        }
        return zzazVar;
    }

    @Override // com.google.android.gms.internal.zzba
    public void zza(zzaz zzazVar) {
        synchronized (this.zzqt) {
            if (!zzazVar.zzbZ()) {
                this.zzqv.remove(zzazVar);
                Iterator<Map.Entry<zzha, zzaz>> it = this.zzqu.entrySet().iterator();
                while (it.hasNext()) {
                    if (it.next().getValue() == zzazVar) {
                        it.remove();
                    }
                }
            }
        }
    }

    public boolean zzf(zzha zzhaVar) {
        boolean z;
        synchronized (this.zzqt) {
            zzaz zzazVar = this.zzqu.get(zzhaVar);
            z = zzazVar != null && zzazVar.zzbZ();
        }
        return z;
    }

    public void zzg(zzha zzhaVar) {
        synchronized (this.zzqt) {
            zzaz zzazVar = this.zzqu.get(zzhaVar);
            if (zzazVar != null) {
                zzazVar.zzbX();
            }
        }
    }

    public void zzh(zzha zzhaVar) {
        synchronized (this.zzqt) {
            zzaz zzazVar = this.zzqu.get(zzhaVar);
            if (zzazVar != null) {
                zzazVar.stop();
            }
        }
    }

    public void zzi(zzha zzhaVar) {
        synchronized (this.zzqt) {
            zzaz zzazVar = this.zzqu.get(zzhaVar);
            if (zzazVar != null) {
                zzazVar.pause();
            }
        }
    }

    public void zzj(zzha zzhaVar) {
        synchronized (this.zzqt) {
            zzaz zzazVar = this.zzqu.get(zzhaVar);
            if (zzazVar != null) {
                zzazVar.resume();
            }
        }
    }
}
