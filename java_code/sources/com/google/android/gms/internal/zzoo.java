package com.google.android.gms.internal;

import android.os.RemoteException;
import com.google.android.gms.internal.zzor;
import com.google.android.gms.nearby.connection.AppMetadata;
/* loaded from: classes.dex */
public abstract class zzoo extends zzor.zza {
    @Override // com.google.android.gms.internal.zzor
    public void onConnectionRequest(String remoteEndpointId, String remoteDeviceId, String remoteEndpointName, byte[] payload) throws RemoteException {
    }

    @Override // com.google.android.gms.internal.zzor
    public void onDisconnected(String remoteEndpointId) throws RemoteException {
    }

    @Override // com.google.android.gms.internal.zzor
    public void onEndpointFound(String endpointId, String deviceId, String applicationId, String name) throws RemoteException {
    }

    @Override // com.google.android.gms.internal.zzor
    public void onEndpointLost(String endpointId) throws RemoteException {
    }

    @Override // com.google.android.gms.internal.zzor
    public void onMessageReceived(String remoteEndpointId, byte[] payload, boolean isReliable) throws RemoteException {
    }

    @Override // com.google.android.gms.internal.zzor
    public void zza(String str, int i, byte[] bArr) throws RemoteException {
    }

    @Override // com.google.android.gms.internal.zzor
    public void zza(String str, String str2, String str3, String str4, AppMetadata appMetadata) throws RemoteException {
    }

    @Override // com.google.android.gms.internal.zzor
    public void zzdP(String str) throws RemoteException {
    }

    @Override // com.google.android.gms.internal.zzor
    public void zzhX(int i) throws RemoteException {
    }

    @Override // com.google.android.gms.internal.zzor
    public void zzhY(int i) throws RemoteException {
    }

    @Override // com.google.android.gms.internal.zzor
    public void zzhZ(int i) throws RemoteException {
    }

    @Override // com.google.android.gms.internal.zzor
    public void zzia(int i) throws RemoteException {
    }

    @Override // com.google.android.gms.internal.zzor
    public void zzib(int i) throws RemoteException {
    }

    @Override // com.google.android.gms.internal.zzor
    public void zzj(int i, String str) throws RemoteException {
    }
}
