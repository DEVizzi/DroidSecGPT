package com.google.android.gms.internal;

import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.common.internal.IAccountAccessor;
import java.util.Set;
/* loaded from: classes.dex */
public interface zzps extends Api.Client {
    void connect();

    void zza(IAccountAccessor iAccountAccessor, Set<Scope> set, com.google.android.gms.signin.internal.zze zzeVar);

    void zza(IAccountAccessor iAccountAccessor, boolean z);

    void zza(com.google.android.gms.common.internal.zzq zzqVar);

    void zzxY();
}
