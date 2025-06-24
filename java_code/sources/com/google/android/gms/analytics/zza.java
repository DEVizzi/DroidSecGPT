package com.google.android.gms.analytics;

import android.net.Uri;
import android.text.TextUtils;
import com.google.android.gms.analytics.internal.zzf;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.internal.zzip;
import com.google.android.gms.internal.zzno;
import com.google.android.gms.internal.zznr;
import com.google.android.gms.internal.zznu;
import java.util.ListIterator;
/* loaded from: classes.dex */
public class zza extends zznr<zza> {
    private final zzf zzIa;
    private boolean zzIb;

    public zza(zzf zzfVar) {
        super(zzfVar.zzhS(), zzfVar.zzhP());
        this.zzIa = zzfVar;
    }

    public void enableAdvertisingIdCollection(boolean enable) {
        this.zzIb = enable;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.internal.zznr
    public void zza(zzno zznoVar) {
        zzip zzipVar = (zzip) zznoVar.zze(zzip.class);
        if (TextUtils.isEmpty(zzipVar.getClientId())) {
            zzipVar.setClientId(this.zzIa.zzih().zziP());
        }
        if (this.zzIb && TextUtils.isEmpty(zzipVar.zzhx())) {
            com.google.android.gms.analytics.internal.zza zzig = this.zzIa.zzig();
            zzipVar.zzaO(zzig.zzhC());
            zzipVar.zzE(zzig.zzhy());
        }
    }

    public void zzaI(String str) {
        zzu.zzcj(str);
        zzaJ(str);
        zzwb().add(new zzb(this.zzIa, str));
    }

    public void zzaJ(String str) {
        Uri zzaK = zzb.zzaK(str);
        ListIterator<zznu> listIterator = zzwb().listIterator();
        while (listIterator.hasNext()) {
            if (zzaK.equals(listIterator.next().zzhe())) {
                listIterator.remove();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzf zzhb() {
        return this.zzIa;
    }

    @Override // com.google.android.gms.internal.zznr
    public zzno zzhc() {
        zzno zzvP = zzwa().zzvP();
        zzvP.zzb(this.zzIa.zzhX().zzix());
        zzvP.zzb(this.zzIa.zzhY().zzjE());
        zzd(zzvP);
        return zzvP;
    }
}
