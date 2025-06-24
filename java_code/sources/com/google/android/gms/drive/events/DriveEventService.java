package com.google.android.gms.drive.events;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.RemoteException;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.google.android.gms.drive.internal.OnEventResponse;
import com.google.android.gms.drive.internal.zzam;
import com.google.android.gms.drive.internal.zzx;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
/* loaded from: classes.dex */
public abstract class DriveEventService extends Service implements ChangeListener, CompletionListener, zzc {
    public static final String ACTION_HANDLE_EVENT = "com.google.android.gms.drive.events.HANDLE_EVENT";
    private final String mName;
    int zzZN;
    private CountDownLatch zzaeb;
    zza zzaec;
    boolean zzaed;

    /* loaded from: classes.dex */
    final class zza extends Handler {
        zza() {
        }

        /* JADX INFO: Access modifiers changed from: private */
        public Message zzb(OnEventResponse onEventResponse) {
            return obtainMessage(1, onEventResponse);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public Message zzpw() {
            return obtainMessage(2);
        }

        @Override // android.os.Handler
        public void handleMessage(Message msg) {
            zzx.zzt("DriveEventService", "handleMessage message type:" + msg.what);
            switch (msg.what) {
                case 1:
                    DriveEventService.this.zza((OnEventResponse) msg.obj);
                    return;
                case 2:
                    getLooper().quit();
                    return;
                default:
                    zzx.zzu("DriveEventService", "Unexpected message type:" + msg.what);
                    return;
            }
        }
    }

    /* loaded from: classes.dex */
    final class zzb extends zzam.zza {
        zzb() {
        }

        @Override // com.google.android.gms.drive.internal.zzam
        public void zzc(OnEventResponse onEventResponse) throws RemoteException {
            synchronized (DriveEventService.this) {
                zzx.zzt("DriveEventService", "onEvent: " + onEventResponse);
                DriveEventService.this.zzpv();
                if (DriveEventService.this.zzaec != null) {
                    DriveEventService.this.zzaec.sendMessage(DriveEventService.this.zzaec.zzb(onEventResponse));
                } else {
                    zzx.zzv("DriveEventService", "Receiving event before initialize is completed.");
                }
            }
        }
    }

    protected DriveEventService() {
        this("DriveEventService");
    }

    protected DriveEventService(String name) {
        this.zzaed = false;
        this.zzZN = -1;
        this.mName = name;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zza(OnEventResponse onEventResponse) {
        DriveEvent zzpO = onEventResponse.zzpO();
        zzx.zzt("DriveEventService", "handleEventMessage: " + zzpO);
        try {
            switch (zzpO.getType()) {
                case 1:
                    onChange((ChangeEvent) zzpO);
                    break;
                case 2:
                    onCompletion((CompletionEvent) zzpO);
                    break;
                case 3:
                default:
                    zzx.zzu(this.mName, "Unhandled event: " + zzpO);
                    break;
                case 4:
                    zza((ChangesAvailableEvent) zzpO);
                    break;
            }
        } catch (Exception e) {
            zzx.zza(this.mName, e, "Error handling event: " + zzpO);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zzpv() throws SecurityException {
        int callingUid = getCallingUid();
        if (callingUid == this.zzZN) {
            return;
        }
        if (!GooglePlayServicesUtil.zzd(this, callingUid)) {
            throw new SecurityException("Caller is not GooglePlayServices");
        }
        this.zzZN = callingUid;
    }

    protected int getCallingUid() {
        return Binder.getCallingUid();
    }

    /* JADX WARN: Type inference failed for: r1v3, types: [com.google.android.gms.drive.events.DriveEventService$1] */
    @Override // android.app.Service
    public final synchronized IBinder onBind(Intent intent) {
        IBinder iBinder;
        if (ACTION_HANDLE_EVENT.equals(intent.getAction())) {
            if (this.zzaec == null && !this.zzaed) {
                this.zzaed = true;
                final CountDownLatch countDownLatch = new CountDownLatch(1);
                this.zzaeb = new CountDownLatch(1);
                new Thread() { // from class: com.google.android.gms.drive.events.DriveEventService.1
                    @Override // java.lang.Thread, java.lang.Runnable
                    public void run() {
                        try {
                            Looper.prepare();
                            DriveEventService.this.zzaec = new zza();
                            DriveEventService.this.zzaed = false;
                            countDownLatch.countDown();
                            zzx.zzt("DriveEventService", "Bound and starting loop");
                            Looper.loop();
                            zzx.zzt("DriveEventService", "Finished loop");
                        } finally {
                            if (DriveEventService.this.zzaeb != null) {
                                DriveEventService.this.zzaeb.countDown();
                            }
                        }
                    }
                }.start();
                try {
                    if (!countDownLatch.await(5000L, TimeUnit.MILLISECONDS)) {
                        zzx.zzv("DriveEventService", "Failed to synchronously initialize event handler.");
                    }
                } catch (InterruptedException e) {
                    throw new RuntimeException("Unable to start event handler", e);
                }
            }
            iBinder = new zzb().asBinder();
        } else {
            iBinder = null;
        }
        return iBinder;
    }

    @Override // com.google.android.gms.drive.events.ChangeListener
    public void onChange(ChangeEvent event) {
        zzx.zzu(this.mName, "Unhandled change event: " + event);
    }

    @Override // com.google.android.gms.drive.events.CompletionListener
    public void onCompletion(CompletionEvent event) {
        zzx.zzu(this.mName, "Unhandled completion event: " + event);
    }

    @Override // android.app.Service
    public synchronized void onDestroy() {
        zzx.zzt("DriveEventService", "onDestroy");
        if (this.zzaec != null) {
            this.zzaec.sendMessage(this.zzaec.zzpw());
            this.zzaec = null;
            try {
                if (!this.zzaeb.await(5000L, TimeUnit.MILLISECONDS)) {
                    zzx.zzu("DriveEventService", "Failed to synchronously quit event handler. Will quit itself");
                }
            } catch (InterruptedException e) {
            }
            this.zzaeb = null;
        }
        super.onDestroy();
    }

    @Override // android.app.Service
    public boolean onUnbind(Intent intent) {
        return true;
    }

    @Override // com.google.android.gms.drive.events.zzc
    public void zza(ChangesAvailableEvent changesAvailableEvent) {
        zzx.zzu(this.mName, "Unhandled changes available event: " + changesAvailableEvent);
    }
}
