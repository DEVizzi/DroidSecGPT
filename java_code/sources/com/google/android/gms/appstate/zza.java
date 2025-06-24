package com.google.android.gms.appstate;

import com.google.android.gms.common.internal.zzt;
/* loaded from: classes.dex */
public final class zza implements AppState {
    private final int zzOf;
    private final String zzOg;
    private final byte[] zzOh;
    private final boolean zzOi;
    private final String zzOj;
    private final byte[] zzOk;

    public zza(AppState appState) {
        this.zzOf = appState.getKey();
        this.zzOg = appState.getLocalVersion();
        this.zzOh = appState.getLocalData();
        this.zzOi = appState.hasConflict();
        this.zzOj = appState.getConflictVersion();
        this.zzOk = appState.getConflictData();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int zza(AppState appState) {
        return zzt.hashCode(Integer.valueOf(appState.getKey()), appState.getLocalVersion(), appState.getLocalData(), Boolean.valueOf(appState.hasConflict()), appState.getConflictVersion(), appState.getConflictData());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean zza(AppState appState, Object obj) {
        if (obj instanceof AppState) {
            if (appState != obj) {
                AppState appState2 = (AppState) obj;
                return zzt.equal(Integer.valueOf(appState2.getKey()), Integer.valueOf(appState.getKey())) && zzt.equal(appState2.getLocalVersion(), appState.getLocalVersion()) && zzt.equal(appState2.getLocalData(), appState.getLocalData()) && zzt.equal(Boolean.valueOf(appState2.hasConflict()), Boolean.valueOf(appState.hasConflict())) && zzt.equal(appState2.getConflictVersion(), appState.getConflictVersion()) && zzt.equal(appState2.getConflictData(), appState.getConflictData());
            }
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String zzb(AppState appState) {
        return zzt.zzt(appState).zzg("Key", Integer.valueOf(appState.getKey())).zzg("LocalVersion", appState.getLocalVersion()).zzg("LocalData", appState.getLocalData()).zzg("HasConflict", Boolean.valueOf(appState.hasConflict())).zzg("ConflictVersion", appState.getConflictVersion()).zzg("ConflictData", appState.getConflictData()).toString();
    }

    public boolean equals(Object obj) {
        return zza(this, obj);
    }

    @Override // com.google.android.gms.appstate.AppState
    public byte[] getConflictData() {
        return this.zzOk;
    }

    @Override // com.google.android.gms.appstate.AppState
    public String getConflictVersion() {
        return this.zzOj;
    }

    @Override // com.google.android.gms.appstate.AppState
    public int getKey() {
        return this.zzOf;
    }

    @Override // com.google.android.gms.appstate.AppState
    public byte[] getLocalData() {
        return this.zzOh;
    }

    @Override // com.google.android.gms.appstate.AppState
    public String getLocalVersion() {
        return this.zzOg;
    }

    @Override // com.google.android.gms.appstate.AppState
    public boolean hasConflict() {
        return this.zzOi;
    }

    public int hashCode() {
        return zza(this);
    }

    @Override // com.google.android.gms.common.data.Freezable
    public boolean isDataValid() {
        return true;
    }

    public String toString() {
        return zzb(this);
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzkT */
    public AppState freeze() {
        return this;
    }
}
