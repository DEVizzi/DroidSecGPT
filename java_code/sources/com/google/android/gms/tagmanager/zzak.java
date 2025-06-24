package com.google.android.gms.tagmanager;

import com.google.android.gms.internal.zzag;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public abstract class zzak {
    private final Set<String> zzaLI;
    private final String zzaLJ;

    public zzak(String str, String... strArr) {
        this.zzaLJ = str;
        this.zzaLI = new HashSet(strArr.length);
        for (String str2 : strArr) {
            this.zzaLI.add(str2);
        }
    }

    public abstract zzag.zza zzE(Map<String, zzag.zza> map);

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean zzg(Set<String> set) {
        return set.containsAll(this.zzaLI);
    }

    public String zzyM() {
        return this.zzaLJ;
    }

    public Set<String> zzyN() {
        return this.zzaLI;
    }

    public abstract boolean zzyh();
}
