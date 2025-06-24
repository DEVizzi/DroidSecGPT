package com.google.android.gms.internal;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
@zzgd
/* loaded from: classes.dex */
public class zzdq implements Iterable<zzdp> {
    private final List<zzdp> zzwE = new LinkedList();

    private zzdp zzc(zzid zzidVar) {
        Iterator<zzdp> it = com.google.android.gms.ads.internal.zzo.zzbH().iterator();
        while (it.hasNext()) {
            zzdp next = it.next();
            if (next.zzoA == zzidVar) {
                return next;
            }
        }
        return null;
    }

    @Override // java.lang.Iterable
    public Iterator<zzdp> iterator() {
        return this.zzwE.iterator();
    }

    public void zza(zzdp zzdpVar) {
        this.zzwE.add(zzdpVar);
    }

    public boolean zza(zzid zzidVar) {
        zzdp zzc = zzc(zzidVar);
        if (zzc != null) {
            zzc.zzwB.abort();
            return true;
        }
        return false;
    }

    public void zzb(zzdp zzdpVar) {
        this.zzwE.remove(zzdpVar);
    }

    public boolean zzb(zzid zzidVar) {
        return zzc(zzidVar) != null;
    }
}
