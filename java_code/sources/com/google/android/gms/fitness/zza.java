package com.google.android.gms.fitness;

import com.google.android.gms.common.Scopes;
import com.google.android.gms.common.api.Scope;
import java.util.HashSet;
import java.util.Set;
/* loaded from: classes.dex */
public final class zza {
    public static Scope zzb(Scope scope) {
        return scope.equals(new Scope(Scopes.FITNESS_ACTIVITY_READ)) ? new Scope(Scopes.FITNESS_ACTIVITY_READ_WRITE) : scope.equals(new Scope(Scopes.FITNESS_LOCATION_READ)) ? new Scope(Scopes.FITNESS_LOCATION_READ_WRITE) : scope.equals(new Scope(Scopes.FITNESS_BODY_READ)) ? new Scope(Scopes.FITNESS_BODY_READ_WRITE) : scope.equals(new Scope(Scopes.FITNESS_NUTRITION_READ)) ? new Scope(Scopes.FITNESS_NUTRITION_READ_WRITE) : scope;
    }

    public static Set<Scope> zzd(Set<Scope> set) {
        HashSet hashSet = new HashSet(set.size());
        for (Scope scope : set) {
            Scope zzb = zzb(scope);
            if (zzb.equals(scope) || !set.contains(zzb)) {
                hashSet.add(scope);
            }
        }
        return hashSet;
    }
}
