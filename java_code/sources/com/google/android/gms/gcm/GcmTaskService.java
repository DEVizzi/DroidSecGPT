package com.google.android.gms.gcm;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Parcelable;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.gcm.zzb;
import java.util.HashSet;
import java.util.Set;
/* loaded from: classes.dex */
public abstract class GcmTaskService extends Service {
    public static final String SERVICE_ACTION_EXECUTE_TASK = "com.google.android.gms.gcm.ACTION_TASK_READY";
    public static final String SERVICE_ACTION_INITIALIZE = "com.google.android.gms.gcm.SERVICE_ACTION_INITIALIZE";
    public static final String SERVICE_PERMISSION = "com.google.android.gms.permission.BIND_NETWORK_TASK_SERVICE";
    private final Set<String> zzavL = new HashSet();
    private int zzavM;

    /* loaded from: classes.dex */
    private class zza extends Thread {
        private final String mTag;
        private final zzb zzavN;

        zza(String str, IBinder iBinder) {
            this.mTag = str;
            this.zzavN = zzb.zza.zzbN(iBinder);
        }

        @Override // java.lang.Thread, java.lang.Runnable
        public void run() {
            try {
                this.zzavN.zzgg(GcmTaskService.this.onRunTask(new TaskParams(this.mTag)));
            } catch (RemoteException e) {
                Log.e("GcmTaskService", "Error reporting result of operation to scheduler for " + this.mTag);
            } finally {
                GcmTaskService.this.zzdc(this.mTag);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zzdc(String str) {
        synchronized (this.zzavL) {
            this.zzavL.remove(str);
            if (this.zzavL.size() == 0) {
                stopSelf(this.zzavM);
            }
        }
    }

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return null;
    }

    public void onInitializeTasks() {
    }

    public abstract int onRunTask(TaskParams taskParams);

    @Override // android.app.Service
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (SERVICE_ACTION_EXECUTE_TASK.equals(intent.getAction())) {
            String stringExtra = intent.getStringExtra("tag");
            Parcelable parcelableExtra = intent.getParcelableExtra("callback");
            if (parcelableExtra == null || !(parcelableExtra instanceof PendingCallback)) {
                Log.e("GcmTaskService", getPackageName() + " " + stringExtra + ": Could not process request, invalid callback.");
            } else {
                synchronized (this.zzavL) {
                    this.zzavL.add(stringExtra);
                    stopSelf(this.zzavM);
                    this.zzavM = startId;
                }
                new zza(stringExtra, ((PendingCallback) parcelableExtra).getIBinder()).start();
            }
        } else if (SERVICE_ACTION_INITIALIZE.equals(intent.getAction())) {
            onInitializeTasks();
            synchronized (this.zzavL) {
                this.zzavM = startId;
                if (this.zzavL.size() == 0) {
                    stopSelf(this.zzavM);
                }
            }
        }
        return 2;
    }
}
