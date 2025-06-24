package com.google.android.gms.internal;

import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.fitness.BleApi;
import com.google.android.gms.fitness.data.BleDevice;
import com.google.android.gms.fitness.request.BleScanCallback;
import com.google.android.gms.fitness.request.ClaimBleDeviceRequest;
import com.google.android.gms.fitness.request.ListClaimedBleDevicesRequest;
import com.google.android.gms.fitness.request.StartBleScanRequest;
import com.google.android.gms.fitness.request.StopBleScanRequest;
import com.google.android.gms.fitness.request.UnclaimBleDeviceRequest;
import com.google.android.gms.fitness.result.BleDevicesResult;
import com.google.android.gms.internal.zzlx;
import com.google.android.gms.internal.zzni;
/* loaded from: classes.dex */
public class zzmz implements BleApi {

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class zza extends zzni.zza {
        private final zza.zzb<BleDevicesResult> zzOs;

        private zza(zza.zzb<BleDevicesResult> zzbVar) {
            this.zzOs = zzbVar;
        }

        @Override // com.google.android.gms.internal.zzni
        public void zza(BleDevicesResult bleDevicesResult) {
            this.zzOs.zzm(bleDevicesResult);
        }
    }

    @Override // com.google.android.gms.fitness.BleApi
    public PendingResult<Status> claimBleDevice(GoogleApiClient client, final BleDevice bleDevice) {
        return client.zzb(new zzlx.zzc(client) { // from class: com.google.android.gms.internal.zzmz.4
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzlx zzlxVar) throws RemoteException {
                ((zzmi) zzlxVar.zznM()).zza(new ClaimBleDeviceRequest(bleDevice.getAddress(), bleDevice, new zzng(this), zzlxVar.getContext().getPackageName()));
            }
        });
    }

    @Override // com.google.android.gms.fitness.BleApi
    public PendingResult<Status> claimBleDevice(GoogleApiClient client, final String deviceAddress) {
        return client.zzb(new zzlx.zzc(client) { // from class: com.google.android.gms.internal.zzmz.3
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzlx zzlxVar) throws RemoteException {
                ((zzmi) zzlxVar.zznM()).zza(new ClaimBleDeviceRequest(deviceAddress, null, new zzng(this), zzlxVar.getContext().getPackageName()));
            }
        });
    }

    @Override // com.google.android.gms.fitness.BleApi
    public PendingResult<BleDevicesResult> listClaimedBleDevices(GoogleApiClient client) {
        return client.zza((GoogleApiClient) new zzlx.zza<BleDevicesResult>(client) { // from class: com.google.android.gms.internal.zzmz.6
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzB */
            public BleDevicesResult createFailedResult(Status status) {
                return BleDevicesResult.zzJ(status);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzlx zzlxVar) throws RemoteException {
                ((zzmi) zzlxVar.zznM()).zza(new ListClaimedBleDevicesRequest(new zza(this), zzlxVar.getContext().getPackageName()));
            }
        });
    }

    @Override // com.google.android.gms.fitness.BleApi
    public PendingResult<Status> startBleScan(GoogleApiClient client, final StartBleScanRequest request) {
        return client.zza((GoogleApiClient) new zzlx.zzc(client) { // from class: com.google.android.gms.internal.zzmz.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzlx zzlxVar) throws RemoteException {
                ((zzmi) zzlxVar.zznM()).zza(new StartBleScanRequest(request, new zzng(this), zzlxVar.getContext().getPackageName()));
            }
        });
    }

    @Override // com.google.android.gms.fitness.BleApi
    public PendingResult<Status> stopBleScan(GoogleApiClient client, final BleScanCallback requestCallback) {
        return client.zza((GoogleApiClient) new zzlx.zzc(client) { // from class: com.google.android.gms.internal.zzmz.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzlx zzlxVar) throws RemoteException {
                ((zzmi) zzlxVar.zznM()).zza(new StopBleScanRequest(requestCallback, new zzng(this), zzlxVar.getContext().getPackageName()));
            }
        });
    }

    @Override // com.google.android.gms.fitness.BleApi
    public PendingResult<Status> unclaimBleDevice(GoogleApiClient client, BleDevice bleDevice) {
        return unclaimBleDevice(client, bleDevice.getAddress());
    }

    @Override // com.google.android.gms.fitness.BleApi
    public PendingResult<Status> unclaimBleDevice(GoogleApiClient client, final String deviceAddress) {
        return client.zzb(new zzlx.zzc(client) { // from class: com.google.android.gms.internal.zzmz.5
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzlx zzlxVar) throws RemoteException {
                ((zzmi) zzlxVar.zznM()).zza(new UnclaimBleDeviceRequest(deviceAddress, new zzng(this), zzlxVar.getContext().getPackageName()));
            }
        });
    }
}
