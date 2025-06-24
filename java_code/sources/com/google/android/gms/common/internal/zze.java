package com.google.android.gms.common.internal;

import android.accounts.Account;
import android.view.View;
import com.google.android.gms.auth.GoogleAuthUtil;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.internal.zzpt;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
/* loaded from: classes.dex */
public final class zze {
    private final Account zzMY;
    private final String zzOd;
    private final String zzOe;
    private final Set<Scope> zzWv;
    private final int zzWw;
    private final View zzWx;
    private final Set<Scope> zzZS;
    private final Map<Api<?>, zza> zzZT;
    private final zzpt zzZU;
    private Integer zzZV;

    /* loaded from: classes.dex */
    public static final class zza {
        public final Set<Scope> zzWJ;
        public final boolean zzZW;

        public zza(Set<Scope> set, boolean z) {
            zzu.zzu(set);
            this.zzWJ = Collections.unmodifiableSet(set);
            this.zzZW = z;
        }
    }

    public zze(Account account, Collection<Scope> collection, Map<Api<?>, zza> map, int i, View view, String str, String str2, zzpt zzptVar) {
        this.zzMY = account;
        this.zzWv = collection == null ? Collections.EMPTY_SET : Collections.unmodifiableSet(new HashSet(collection));
        this.zzZT = map == null ? Collections.EMPTY_MAP : map;
        this.zzWx = view;
        this.zzWw = i;
        this.zzOe = str;
        this.zzOd = str2;
        this.zzZU = zzptVar;
        HashSet hashSet = new HashSet(this.zzWv);
        for (zza zzaVar : this.zzZT.values()) {
            hashSet.addAll(zzaVar.zzWJ);
        }
        this.zzZS = Collections.unmodifiableSet(hashSet);
    }

    public Account getAccount() {
        return this.zzMY;
    }

    @Deprecated
    public String getAccountName() {
        if (this.zzMY != null) {
            return this.zzMY.name;
        }
        return null;
    }

    public void zza(Integer num) {
        this.zzZV = num;
    }

    public Set<Scope> zzb(Api<?> api) {
        zza zzaVar = this.zzZT.get(api);
        if (zzaVar == null || zzaVar.zzWJ.isEmpty()) {
            return this.zzWv;
        }
        HashSet hashSet = new HashSet(this.zzWv);
        hashSet.addAll(zzaVar.zzWJ);
        return hashSet;
    }

    public View zznA() {
        return this.zzWx;
    }

    public zzpt zznB() {
        return this.zzZU;
    }

    public Integer zznC() {
        return this.zzZV;
    }

    @Deprecated
    public String zzns() {
        return zznt().name;
    }

    public Account zznt() {
        return this.zzMY != null ? this.zzMY : new Account("<<default account>>", GoogleAuthUtil.GOOGLE_ACCOUNT_TYPE);
    }

    public int zznu() {
        return this.zzWw;
    }

    public Set<Scope> zznv() {
        return this.zzWv;
    }

    public Set<Scope> zznw() {
        return this.zzZS;
    }

    public Map<Api<?>, zza> zznx() {
        return this.zzZT;
    }

    public String zzny() {
        return this.zzOe;
    }

    public String zznz() {
        return this.zzOd;
    }
}
