package com.google.android.gms.internal;

import java.util.ArrayList;
import java.util.List;
/* loaded from: classes.dex */
public class zzqd {
    private final List<zzpy> zzaPn = new ArrayList();

    public String getId() {
        StringBuilder sb = new StringBuilder();
        boolean z = true;
        for (zzpy zzpyVar : this.zzaPn) {
            if (z) {
                z = false;
            } else {
                sb.append("#");
            }
            sb.append(zzpyVar.getContainerId());
        }
        return sb.toString();
    }

    public List<zzpy> zzAf() {
        return this.zzaPn;
    }

    public zzqd zzb(zzpy zzpyVar) throws IllegalArgumentException {
        com.google.android.gms.common.internal.zzu.zzu(zzpyVar);
        for (zzpy zzpyVar2 : this.zzaPn) {
            if (zzpyVar2.getContainerId().equals(zzpyVar.getContainerId())) {
                throw new IllegalArgumentException("The container is already being requested. " + zzpyVar.getContainerId());
            }
        }
        this.zzaPn.add(zzpyVar);
        return this;
    }
}
