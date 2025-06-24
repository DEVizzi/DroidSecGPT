package com.google.android.gms.plus.internal;

import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.server.response.SafeParcelResponse;
import com.google.android.gms.plus.internal.model.people.PersonEntity;
import com.google.android.gms.plus.internal.zzb;
/* loaded from: classes.dex */
public abstract class zza extends zzb.zza {
    @Override // com.google.android.gms.plus.internal.zzb
    public void zza(int i, Bundle bundle, Bundle bundle2) throws RemoteException {
    }

    @Override // com.google.android.gms.plus.internal.zzb
    public void zza(int i, Bundle bundle, ParcelFileDescriptor parcelFileDescriptor) throws RemoteException {
    }

    @Override // com.google.android.gms.plus.internal.zzb
    public final void zza(int i, Bundle bundle, SafeParcelResponse safeParcelResponse) {
    }

    @Override // com.google.android.gms.plus.internal.zzb
    public void zza(int i, PersonEntity personEntity) {
    }

    @Override // com.google.android.gms.plus.internal.zzb
    public void zza(DataHolder dataHolder, String str) {
    }

    @Override // com.google.android.gms.plus.internal.zzb
    public void zza(DataHolder dataHolder, String str, String str2) {
    }

    @Override // com.google.android.gms.plus.internal.zzb
    public void zzaO(Status status) {
    }

    @Override // com.google.android.gms.plus.internal.zzb
    public void zzdV(String str) throws RemoteException {
    }

    @Override // com.google.android.gms.plus.internal.zzb
    public void zzdW(String str) {
    }

    @Override // com.google.android.gms.plus.internal.zzb
    public void zzi(int i, Bundle bundle) {
    }
}
