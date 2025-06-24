package com.google.android.gms.fitness.request;

import android.os.RemoteException;
import com.google.android.gms.fitness.data.BleDevice;
import com.google.android.gms.fitness.request.zzn;
import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
public class zza extends zzn.zza {
    private final BleScanCallback zzalI;

    /* renamed from: com.google.android.gms.fitness.request.zza$zza  reason: collision with other inner class name */
    /* loaded from: classes.dex */
    public static class C0064zza {
        private static final C0064zza zzalJ = new C0064zza();
        private final Map<BleScanCallback, zza> zzalK = new HashMap();

        private C0064zza() {
        }

        public static C0064zza zzqS() {
            return zzalJ;
        }

        public zza zza(BleScanCallback bleScanCallback) {
            zza zzaVar;
            synchronized (this.zzalK) {
                zzaVar = this.zzalK.get(bleScanCallback);
                if (zzaVar == null) {
                    zzaVar = new zza(bleScanCallback);
                    this.zzalK.put(bleScanCallback, zzaVar);
                }
            }
            return zzaVar;
        }

        public zza zzb(BleScanCallback bleScanCallback) {
            zza zzaVar;
            synchronized (this.zzalK) {
                zzaVar = this.zzalK.get(bleScanCallback);
                if (zzaVar == null) {
                    zzaVar = new zza(bleScanCallback);
                }
            }
            return zzaVar;
        }
    }

    private zza(BleScanCallback bleScanCallback) {
        this.zzalI = (BleScanCallback) com.google.android.gms.common.internal.zzu.zzu(bleScanCallback);
    }

    @Override // com.google.android.gms.fitness.request.zzn
    public void onDeviceFound(BleDevice device) throws RemoteException {
        this.zzalI.onDeviceFound(device);
    }

    @Override // com.google.android.gms.fitness.request.zzn
    public void onScanStopped() throws RemoteException {
        this.zzalI.onScanStopped();
    }
}
