package com.google.android.gms.fitness.data;

import android.os.RemoteException;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.fitness.data.zzj;
import com.google.android.gms.fitness.request.OnDataPointListener;
import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
public class zzk extends zzj.zza {
    private final OnDataPointListener zzakC;

    /* loaded from: classes.dex */
    public static class zza {
        private static final zza zzakD = new zza();
        private final Map<OnDataPointListener, zzk> zzakE = new HashMap();

        private zza() {
        }

        public static zza zzqH() {
            return zzakD;
        }

        public zzk zza(OnDataPointListener onDataPointListener) {
            zzk zzkVar;
            synchronized (this.zzakE) {
                zzkVar = this.zzakE.get(onDataPointListener);
                if (zzkVar == null) {
                    zzkVar = new zzk(onDataPointListener);
                    this.zzakE.put(onDataPointListener, zzkVar);
                }
            }
            return zzkVar;
        }

        public zzk zzb(OnDataPointListener onDataPointListener) {
            zzk zzkVar;
            synchronized (this.zzakE) {
                zzkVar = this.zzakE.get(onDataPointListener);
            }
            return zzkVar;
        }

        public zzk zzc(OnDataPointListener onDataPointListener) {
            zzk remove;
            synchronized (this.zzakE) {
                remove = this.zzakE.remove(onDataPointListener);
                if (remove == null) {
                    remove = new zzk(onDataPointListener);
                }
            }
            return remove;
        }
    }

    private zzk(OnDataPointListener onDataPointListener) {
        this.zzakC = (OnDataPointListener) zzu.zzu(onDataPointListener);
    }

    @Override // com.google.android.gms.fitness.data.zzj
    public void zzc(DataPoint dataPoint) throws RemoteException {
        this.zzakC.onDataPoint(dataPoint);
    }
}
