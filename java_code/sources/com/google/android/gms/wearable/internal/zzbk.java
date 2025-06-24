package com.google.android.gms.wearable.internal;

import android.content.Context;
import android.content.IntentFilter;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.drive.DriveFile;
import com.google.android.gms.wearable.Asset;
import com.google.android.gms.wearable.CapabilityApi;
import com.google.android.gms.wearable.Channel;
import com.google.android.gms.wearable.ChannelApi;
import com.google.android.gms.wearable.DataApi;
import com.google.android.gms.wearable.DataItemAsset;
import com.google.android.gms.wearable.DataItemBuffer;
import com.google.android.gms.wearable.MessageApi;
import com.google.android.gms.wearable.NodeApi;
import com.google.android.gms.wearable.PutDataRequest;
import com.google.android.gms.wearable.internal.zzat;
import com.google.android.gms.wearable.internal.zzbj;
import com.google.android.gms.wearable.zza;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
/* loaded from: classes.dex */
public class zzbk extends com.google.android.gms.common.internal.zzi<zzat> {
    private final ExecutorService zzaNb;
    private final zzau<zza.InterfaceC0242zza> zzaUR;
    private final zzau<ChannelApi.ChannelListener> zzaUS;
    private final zzau<DataApi.DataListener> zzaUT;
    private final zzau<MessageApi.MessageListener> zzaUU;
    private final zzau<NodeApi.NodeListener> zzaUV;
    private final zzau<NodeApi.zza> zzaUW;
    private final Map<String, zzau<CapabilityApi.CapabilityListener>> zzaUX;

    public zzbk(Context context, Looper looper, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener, com.google.android.gms.common.internal.zze zzeVar) {
        super(context, looper, 14, connectionCallbacks, onConnectionFailedListener, zzeVar);
        this.zzaNb = Executors.newCachedThreadPool();
        this.zzaUR = new zzau<>();
        this.zzaUS = new zzau<>();
        this.zzaUT = new zzau<>();
        this.zzaUU = new zzau<>();
        this.zzaUV = new zzau<>();
        this.zzaUW = new zzau<>();
        this.zzaUX = new HashMap();
    }

    private FutureTask<Boolean> zza(final ParcelFileDescriptor parcelFileDescriptor, final byte[] bArr) {
        return new FutureTask<>(new Callable<Boolean>() { // from class: com.google.android.gms.wearable.internal.zzbk.1
            @Override // java.util.concurrent.Callable
            /* renamed from: zzBg */
            public Boolean call() {
                if (Log.isLoggable("WearableClient", 3)) {
                    Log.d("WearableClient", "processAssets: writing data to FD : " + parcelFileDescriptor);
                }
                ParcelFileDescriptor.AutoCloseOutputStream autoCloseOutputStream = new ParcelFileDescriptor.AutoCloseOutputStream(parcelFileDescriptor);
                try {
                    try {
                        autoCloseOutputStream.write(bArr);
                        autoCloseOutputStream.flush();
                        if (Log.isLoggable("WearableClient", 3)) {
                            Log.d("WearableClient", "processAssets: wrote data: " + parcelFileDescriptor);
                        }
                        try {
                            if (Log.isLoggable("WearableClient", 3)) {
                                Log.d("WearableClient", "processAssets: closing: " + parcelFileDescriptor);
                            }
                            autoCloseOutputStream.close();
                            return true;
                        } catch (IOException e) {
                            return true;
                        }
                    } catch (IOException e2) {
                        Log.w("WearableClient", "processAssets: writing data failed: " + parcelFileDescriptor);
                        return false;
                    }
                } finally {
                    try {
                        if (Log.isLoggable("WearableClient", 3)) {
                            Log.d("WearableClient", "processAssets: closing: " + parcelFileDescriptor);
                        }
                        autoCloseOutputStream.close();
                    } catch (IOException e3) {
                    }
                }
            }
        });
    }

    private FutureTask<Void> zzb(final zza.zzb<Status> zzbVar, final String str, final Uri uri, final long j, final long j2) {
        com.google.android.gms.common.internal.zzu.zzu(zzbVar);
        com.google.android.gms.common.internal.zzu.zzu(str);
        com.google.android.gms.common.internal.zzu.zzu(uri);
        com.google.android.gms.common.internal.zzu.zzb(j >= 0, "startOffset is negative: %s", Long.valueOf(j));
        com.google.android.gms.common.internal.zzu.zzb(j2 >= -1, "invalid length: %s", Long.valueOf(j2));
        return new FutureTask<>(new Runnable() { // from class: com.google.android.gms.wearable.internal.zzbk.3
            @Override // java.lang.Runnable
            public void run() {
                if (Log.isLoggable("WearableClient", 2)) {
                    Log.v("WearableClient", "Executing sendFileToChannelTask");
                }
                if (!"file".equals(uri.getScheme())) {
                    Log.w("WearableClient", "Channel.sendFile used with non-file URI");
                    zzbVar.zzr(new Status(10, "Channel.sendFile used with non-file URI"));
                    return;
                }
                File file = new File(uri.getPath());
                try {
                    ParcelFileDescriptor open = ParcelFileDescriptor.open(file, DriveFile.MODE_READ_ONLY);
                    try {
                        try {
                            zzbk.this.zznM().zza(new zzbj.zzr(zzbVar), str, open, j, j2);
                        } catch (RemoteException e) {
                            Log.w("WearableClient", "Channel.sendFile failed.", e);
                            zzbVar.zzr(new Status(8));
                            try {
                                open.close();
                            } catch (IOException e2) {
                                Log.w("WearableClient", "Failed to close sourceFd", e2);
                            }
                        }
                    } finally {
                        try {
                            open.close();
                        } catch (IOException e3) {
                            Log.w("WearableClient", "Failed to close sourceFd", e3);
                        }
                    }
                } catch (FileNotFoundException e4) {
                    Log.w("WearableClient", "File couldn't be opened for Channel.sendFile: " + file);
                    zzbVar.zzr(new Status(13));
                }
            }
        }, null);
    }

    private FutureTask<Void> zzb(final zza.zzb<Status> zzbVar, final String str, final Uri uri, final boolean z) {
        com.google.android.gms.common.internal.zzu.zzu(zzbVar);
        com.google.android.gms.common.internal.zzu.zzu(str);
        com.google.android.gms.common.internal.zzu.zzu(uri);
        return new FutureTask<>(new Runnable() { // from class: com.google.android.gms.wearable.internal.zzbk.2
            /* JADX WARN: Multi-variable type inference failed */
            /* JADX WARN: Type inference failed for: r1v12 */
            /* JADX WARN: Type inference failed for: r1v16 */
            /* JADX WARN: Type inference failed for: r1v17 */
            /* JADX WARN: Type inference failed for: r1v18 */
            /* JADX WARN: Type inference failed for: r1v19 */
            /* JADX WARN: Type inference failed for: r1v3, types: [java.lang.Object, java.io.File] */
            @Override // java.lang.Runnable
            public void run() {
                if (Log.isLoggable("WearableClient", 2)) {
                    Log.v("WearableClient", "Executing receiveFileFromChannelTask");
                }
                if (!"file".equals(uri.getScheme())) {
                    Log.w("WearableClient", "Channel.receiveFile used with non-file URI");
                    zzbVar.zzr(new Status(10, "Channel.receiveFile used with non-file URI"));
                    return;
                }
                ParcelFileDescriptor file = new File(uri.getPath());
                try {
                    try {
                        ParcelFileDescriptor open = ParcelFileDescriptor.open(file, (z ? 33554432 : 0) | DriveFile.MODE_WRITE_ONLY);
                        try {
                            zzbk.this.zznM().zza(new zzbj.zzu(zzbVar), str, open);
                        } catch (RemoteException e) {
                            Log.w("WearableClient", "Channel.receiveFile failed.", e);
                            zzbVar.zzr(new Status(8));
                            try {
                                open.close();
                                file = open;
                            } catch (IOException e2) {
                                Log.w("WearableClient", "Failed to close targetFd", e2);
                                file = "WearableClient";
                            }
                        }
                    } catch (FileNotFoundException e3) {
                        Log.w("WearableClient", "File couldn't be opened for Channel.receiveFile: " + ((Object) file));
                        zzbVar.zzr(new Status(13));
                    }
                } finally {
                    try {
                        file.close();
                    } catch (IOException e4) {
                        Log.w("WearableClient", "Failed to close targetFd", e4);
                    }
                }
            }
        }, null);
    }

    private zzau<CapabilityApi.CapabilityListener> zzfh(String str) {
        zzau<CapabilityApi.CapabilityListener> zzauVar = this.zzaUX.get(str);
        if (zzauVar == null) {
            zzau<CapabilityApi.CapabilityListener> zzauVar2 = new zzau<>();
            this.zzaUX.put(str, zzauVar2);
            return zzauVar2;
        }
        return zzauVar;
    }

    @Override // com.google.android.gms.common.internal.zzi, com.google.android.gms.common.api.Api.Client
    public void disconnect() {
        this.zzaUR.zzb(this);
        this.zzaUT.zzb(this);
        this.zzaUU.zzb(this);
        this.zzaUV.zzb(this);
        this.zzaUW.zzb(this);
        synchronized (this.zzaUX) {
            for (zzau<CapabilityApi.CapabilityListener> zzauVar : this.zzaUX.values()) {
                zzauVar.zzb(this);
            }
        }
        super.disconnect();
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.wearable.internal.IWearableService";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return "com.google.android.gms.wearable.BIND";
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    public void zza(int i, IBinder iBinder, Bundle bundle, int i2) {
        if (Log.isLoggable("WearableClient", 2)) {
            Log.d("WearableClient", "onPostInitHandler: statusCode " + i);
        }
        if (i == 0) {
            this.zzaUR.zzdR(iBinder);
            this.zzaUT.zzdR(iBinder);
            this.zzaUU.zzdR(iBinder);
            this.zzaUV.zzdR(iBinder);
            this.zzaUW.zzdR(iBinder);
            synchronized (this.zzaUX) {
                for (zzau<CapabilityApi.CapabilityListener> zzauVar : this.zzaUX.values()) {
                    zzauVar.zzdR(iBinder);
                }
            }
        }
        super.zza(i, iBinder, bundle, i2);
    }

    public void zza(zza.zzb<DataApi.DataItemResult> zzbVar, Uri uri) throws RemoteException {
        zznM().zza(new zzbj.zzk(zzbVar), uri);
    }

    public void zza(zza.zzb<DataItemBuffer> zzbVar, Uri uri, int i) throws RemoteException {
        zznM().zza(new zzbj.zzl(zzbVar), uri, i);
    }

    public void zza(zza.zzb<DataApi.GetFdForAssetResult> zzbVar, Asset asset) throws RemoteException {
        zznM().zza(new zzbj.zzm(zzbVar), asset);
    }

    public void zza(zza.zzb<Status> zzbVar, CapabilityApi.CapabilityListener capabilityListener, String str) throws RemoteException {
        synchronized (this.zzaUX) {
            zzfh(str).zza(this, zzbVar, capabilityListener, zzbl.zza(capabilityListener, str));
        }
    }

    public void zza(zza.zzb<Status> zzbVar, ChannelApi.ChannelListener channelListener, String str) throws RemoteException {
        if (str == null) {
            this.zzaUS.zza(this, zzbVar, channelListener, zzbl.zzb(channelListener));
            return;
        }
        zzbf zzbfVar = new zzbf(str, channelListener);
        this.zzaUS.zza(this, zzbVar, zzbfVar, zzbl.zza(zzbfVar, str));
    }

    public void zza(zza.zzb<Status> zzbVar, DataApi.DataListener dataListener) throws RemoteException {
        this.zzaUT.zza(this, zzbVar, dataListener);
    }

    public void zza(zza.zzb<Status> zzbVar, DataApi.DataListener dataListener, IntentFilter[] intentFilterArr) throws RemoteException {
        this.zzaUT.zza(this, zzbVar, dataListener, zzbl.zza(dataListener, intentFilterArr));
    }

    public void zza(zza.zzb<DataApi.GetFdForAssetResult> zzbVar, DataItemAsset dataItemAsset) throws RemoteException {
        zza(zzbVar, Asset.createFromRef(dataItemAsset.getId()));
    }

    public void zza(zza.zzb<Status> zzbVar, MessageApi.MessageListener messageListener) throws RemoteException {
        this.zzaUU.zza(this, zzbVar, messageListener);
    }

    public void zza(zza.zzb<Status> zzbVar, MessageApi.MessageListener messageListener, IntentFilter[] intentFilterArr) throws RemoteException {
        this.zzaUU.zza(this, zzbVar, messageListener, zzbl.zza(messageListener, intentFilterArr));
    }

    public void zza(zza.zzb<Status> zzbVar, NodeApi.NodeListener nodeListener) throws RemoteException {
        this.zzaUV.zza(this, zzbVar, nodeListener, zzbl.zza(nodeListener));
    }

    public void zza(zza.zzb<DataApi.DataItemResult> zzbVar, PutDataRequest putDataRequest) throws RemoteException {
        for (Map.Entry<String, Asset> entry : putDataRequest.getAssets().entrySet()) {
            Asset value = entry.getValue();
            if (value.getData() == null && value.getDigest() == null && value.getFd() == null && value.getUri() == null) {
                throw new IllegalArgumentException("Put for " + putDataRequest.getUri() + " contains invalid asset: " + value);
            }
        }
        PutDataRequest zzn = PutDataRequest.zzn(putDataRequest.getUri());
        zzn.setData(putDataRequest.getData());
        ArrayList arrayList = new ArrayList();
        for (Map.Entry<String, Asset> entry2 : putDataRequest.getAssets().entrySet()) {
            Asset value2 = entry2.getValue();
            if (value2.getData() == null) {
                zzn.putAsset(entry2.getKey(), entry2.getValue());
            } else {
                try {
                    ParcelFileDescriptor[] createPipe = ParcelFileDescriptor.createPipe();
                    if (Log.isLoggable("WearableClient", 3)) {
                        Log.d("WearableClient", "processAssets: replacing data with FD in asset: " + value2 + " read:" + createPipe[0] + " write:" + createPipe[1]);
                    }
                    zzn.putAsset(entry2.getKey(), Asset.createFromFd(createPipe[0]));
                    FutureTask<Boolean> zza = zza(createPipe[1], value2.getData());
                    arrayList.add(zza);
                    this.zzaNb.submit(zza);
                } catch (IOException e) {
                    throw new IllegalStateException("Unable to create ParcelFileDescriptor for asset in request: " + putDataRequest, e);
                }
            }
        }
        zznM().zza(new zzbj.zzq(zzbVar, arrayList), zzn);
    }

    public void zza(zza.zzb<Status> zzbVar, String str, Uri uri, long j, long j2) {
        try {
            this.zzaNb.submit(zzb(zzbVar, str, uri, j, j2));
        } catch (RuntimeException e) {
            zzbVar.zzr(new Status(8));
            throw e;
        }
    }

    public void zza(zza.zzb<Status> zzbVar, String str, Uri uri, boolean z) {
        try {
            this.zzaNb.submit(zzb(zzbVar, str, uri, z));
        } catch (RuntimeException e) {
            zzbVar.zzr(new Status(8));
            throw e;
        }
    }

    public void zza(zza.zzb<MessageApi.SendMessageResult> zzbVar, String str, String str2, byte[] bArr) throws RemoteException {
        zznM().zza(new zzbj.zzt(zzbVar), str, str2, bArr);
    }

    public void zzb(zza.zzb<DataApi.DeleteDataItemsResult> zzbVar, Uri uri, int i) throws RemoteException {
        zznM().zzb(new zzbj.zze(zzbVar), uri, i);
    }

    public void zzb(zza.zzb<Status> zzbVar, CapabilityApi.CapabilityListener capabilityListener, String str) throws RemoteException {
        synchronized (this.zzaUX) {
            zzau<CapabilityApi.CapabilityListener> zzfh = zzfh(str);
            zzfh.zza(this, zzbVar, capabilityListener);
            if (zzfh.isEmpty()) {
                this.zzaUX.remove(str);
            }
        }
    }

    public void zzb(zza.zzb<Status> zzbVar, ChannelApi.ChannelListener channelListener, String str) throws RemoteException {
        if (str == null) {
            this.zzaUS.zza(this, zzbVar, channelListener);
            return;
        }
        this.zzaUS.zza(this, zzbVar, new zzbf(str, channelListener));
    }

    public void zzb(zza.zzb<Status> zzbVar, NodeApi.NodeListener nodeListener) throws RemoteException {
        this.zzaUV.zza(this, zzbVar, nodeListener);
    }

    public void zzd(zza.zzb<CapabilityApi.GetAllCapabilitiesResult> zzbVar, int i) throws RemoteException {
        zznM().zza(new zzbj.zzf(zzbVar), i);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: zzdS */
    public zzat zzT(IBinder iBinder) {
        return zzat.zza.zzdQ(iBinder);
    }

    public void zze(zza.zzb<ChannelApi.OpenChannelResult> zzbVar, String str, String str2) throws RemoteException {
        zznM().zza(new zzbj.zzp(zzbVar), str, str2);
    }

    public void zzg(zza.zzb<CapabilityApi.GetCapabilityResult> zzbVar, String str, int i) throws RemoteException {
        zznM().zza(new zzbj.zzg(zzbVar), str, i);
    }

    public void zzh(zza.zzb<Status> zzbVar, String str, int i) throws RemoteException {
        zznM().zzb(new zzbj.zzd(zzbVar), str, i);
    }

    public void zzl(zza.zzb<DataItemBuffer> zzbVar) throws RemoteException {
        zznM().zzb(new zzbj.zzl(zzbVar));
    }

    public void zzm(zza.zzb<NodeApi.GetLocalNodeResult> zzbVar) throws RemoteException {
        zznM().zzc(new zzbj.zzn(zzbVar));
    }

    public void zzn(zza.zzb<NodeApi.GetConnectedNodesResult> zzbVar) throws RemoteException {
        zznM().zzd(new zzbj.zzj(zzbVar));
    }

    public void zzr(zza.zzb<CapabilityApi.AddLocalCapabilityResult> zzbVar, String str) throws RemoteException {
        zznM().zzd(new zzbj.zza(zzbVar), str);
    }

    public void zzs(zza.zzb<CapabilityApi.RemoveLocalCapabilityResult> zzbVar, String str) throws RemoteException {
        zznM().zze(new zzbj.zzs(zzbVar), str);
    }

    public void zzt(zza.zzb<Status> zzbVar, String str) throws RemoteException {
        zznM().zzf(new zzbj.zzc(zzbVar), str);
    }

    public void zzu(zza.zzb<Channel.GetInputStreamResult> zzbVar, String str) throws RemoteException {
        zzq zzqVar = new zzq();
        zznM().zza(new zzbj.zzh(zzbVar, zzqVar), zzqVar, str);
    }

    public void zzv(zza.zzb<Channel.GetOutputStreamResult> zzbVar, String str) throws RemoteException {
        zzq zzqVar = new zzq();
        zznM().zzb(new zzbj.zzi(zzbVar, zzqVar), zzqVar, str);
    }
}
