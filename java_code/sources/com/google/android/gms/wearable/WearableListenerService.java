package com.google.android.gms.wearable;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.util.Log;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.wearable.CapabilityApi;
import com.google.android.gms.wearable.ChannelApi;
import com.google.android.gms.wearable.DataApi;
import com.google.android.gms.wearable.MessageApi;
import com.google.android.gms.wearable.NodeApi;
import com.google.android.gms.wearable.internal.AncsNotificationParcelable;
import com.google.android.gms.wearable.internal.CapabilityInfoParcelable;
import com.google.android.gms.wearable.internal.ChannelEventParcelable;
import com.google.android.gms.wearable.internal.MessageEventParcelable;
import com.google.android.gms.wearable.internal.NodeParcelable;
import com.google.android.gms.wearable.internal.zzas;
import java.util.List;
/* loaded from: classes.dex */
public abstract class WearableListenerService extends Service implements CapabilityApi.CapabilityListener, ChannelApi.ChannelListener, DataApi.DataListener, MessageApi.MessageListener, NodeApi.NodeListener, NodeApi.zza {
    public static final String BIND_LISTENER_INTENT_ACTION = "com.google.android.gms.wearable.BIND_LISTENER";
    private boolean zzJA;
    private String zzMZ;
    private IBinder zzZQ;
    private Handler zzaTd;
    private volatile int zzZN = -1;
    private Object zzaTe = new Object();

    /* loaded from: classes.dex */
    private class zza extends zzas.zza {
        boolean zzaTf;

        zza() {
            this.zzaTf = false;
            this.zzaTf = WearableListenerService.this instanceof zzh;
        }

        @Override // com.google.android.gms.wearable.internal.zzas
        public void onConnectedNodes(final List<NodeParcelable> connectedNodes) {
            if (Log.isLoggable("WearableLS", 3)) {
                Log.d("WearableLS", "onConnectedNodes: " + WearableListenerService.this.zzMZ + ": " + connectedNodes);
            }
            WearableListenerService.this.zzAS();
            synchronized (WearableListenerService.this.zzaTe) {
                if (WearableListenerService.this.zzJA) {
                    return;
                }
                WearableListenerService.this.zzaTd.post(new Runnable() { // from class: com.google.android.gms.wearable.WearableListenerService.zza.5
                    @Override // java.lang.Runnable
                    public void run() {
                        WearableListenerService.this.onConnectedNodes(connectedNodes);
                    }
                });
            }
        }

        @Override // com.google.android.gms.wearable.internal.zzas
        public void zza(final AncsNotificationParcelable ancsNotificationParcelable) {
            if (Log.isLoggable("WearableLS", 3)) {
                Log.d("WearableLS", "onNotificationReceived: " + ancsNotificationParcelable);
            }
            if (this.zzaTf) {
                WearableListenerService.this.zzAS();
                final zzh zzhVar = (zzh) WearableListenerService.this;
                synchronized (WearableListenerService.this.zzaTe) {
                    if (!WearableListenerService.this.zzJA) {
                        WearableListenerService.this.zzaTd.post(new Runnable() { // from class: com.google.android.gms.wearable.WearableListenerService.zza.7
                            @Override // java.lang.Runnable
                            public void run() {
                                zzhVar.zza(ancsNotificationParcelable);
                            }
                        });
                    }
                }
            }
        }

        @Override // com.google.android.gms.wearable.internal.zzas
        public void zza(final CapabilityInfoParcelable capabilityInfoParcelable) {
            if (Log.isLoggable("WearableLS", 3)) {
                Log.d("WearableLS", "onConnectedCapabilityChanged: " + capabilityInfoParcelable);
            }
            WearableListenerService.this.zzAS();
            synchronized (WearableListenerService.this.zzaTe) {
                if (WearableListenerService.this.zzJA) {
                    return;
                }
                WearableListenerService.this.zzaTd.post(new Runnable() { // from class: com.google.android.gms.wearable.WearableListenerService.zza.6
                    @Override // java.lang.Runnable
                    public void run() {
                        WearableListenerService.this.onCapabilityChanged(capabilityInfoParcelable);
                    }
                });
            }
        }

        @Override // com.google.android.gms.wearable.internal.zzas
        public void zza(final ChannelEventParcelable channelEventParcelable) {
            if (Log.isLoggable("WearableLS", 3)) {
                Log.d("WearableLS", "onChannelEvent: " + channelEventParcelable);
            }
            WearableListenerService.this.zzAS();
            synchronized (WearableListenerService.this.zzaTe) {
                if (WearableListenerService.this.zzJA) {
                    return;
                }
                WearableListenerService.this.zzaTd.post(new Runnable() { // from class: com.google.android.gms.wearable.WearableListenerService.zza.8
                    @Override // java.lang.Runnable
                    public void run() {
                        channelEventParcelable.zza(WearableListenerService.this);
                    }
                });
            }
        }

        @Override // com.google.android.gms.wearable.internal.zzas
        public void zza(final MessageEventParcelable messageEventParcelable) {
            if (Log.isLoggable("WearableLS", 3)) {
                Log.d("WearableLS", "onMessageReceived: " + messageEventParcelable);
            }
            WearableListenerService.this.zzAS();
            synchronized (WearableListenerService.this.zzaTe) {
                if (WearableListenerService.this.zzJA) {
                    return;
                }
                WearableListenerService.this.zzaTd.post(new Runnable() { // from class: com.google.android.gms.wearable.WearableListenerService.zza.2
                    @Override // java.lang.Runnable
                    public void run() {
                        WearableListenerService.this.onMessageReceived(messageEventParcelable);
                    }
                });
            }
        }

        @Override // com.google.android.gms.wearable.internal.zzas
        public void zza(final NodeParcelable nodeParcelable) {
            if (Log.isLoggable("WearableLS", 3)) {
                Log.d("WearableLS", "onPeerConnected: " + WearableListenerService.this.zzMZ + ": " + nodeParcelable);
            }
            WearableListenerService.this.zzAS();
            synchronized (WearableListenerService.this.zzaTe) {
                if (WearableListenerService.this.zzJA) {
                    return;
                }
                WearableListenerService.this.zzaTd.post(new Runnable() { // from class: com.google.android.gms.wearable.WearableListenerService.zza.3
                    @Override // java.lang.Runnable
                    public void run() {
                        WearableListenerService.this.onPeerConnected(nodeParcelable);
                    }
                });
            }
        }

        @Override // com.google.android.gms.wearable.internal.zzas
        public void zzac(final DataHolder dataHolder) {
            if (Log.isLoggable("WearableLS", 3)) {
                Log.d("WearableLS", "onDataItemChanged: " + WearableListenerService.this.zzMZ + ": " + dataHolder);
            }
            WearableListenerService.this.zzAS();
            synchronized (WearableListenerService.this.zzaTe) {
                if (WearableListenerService.this.zzJA) {
                    dataHolder.close();
                } else {
                    WearableListenerService.this.zzaTd.post(new Runnable() { // from class: com.google.android.gms.wearable.WearableListenerService.zza.1
                        @Override // java.lang.Runnable
                        public void run() {
                            DataEventBuffer dataEventBuffer = new DataEventBuffer(dataHolder);
                            try {
                                WearableListenerService.this.onDataChanged(dataEventBuffer);
                            } finally {
                                dataEventBuffer.release();
                            }
                        }
                    });
                }
            }
        }

        @Override // com.google.android.gms.wearable.internal.zzas
        public void zzb(final NodeParcelable nodeParcelable) {
            if (Log.isLoggable("WearableLS", 3)) {
                Log.d("WearableLS", "onPeerDisconnected: " + WearableListenerService.this.zzMZ + ": " + nodeParcelable);
            }
            WearableListenerService.this.zzAS();
            synchronized (WearableListenerService.this.zzaTe) {
                if (WearableListenerService.this.zzJA) {
                    return;
                }
                WearableListenerService.this.zzaTd.post(new Runnable() { // from class: com.google.android.gms.wearable.WearableListenerService.zza.4
                    @Override // java.lang.Runnable
                    public void run() {
                        WearableListenerService.this.onPeerDisconnected(nodeParcelable);
                    }
                });
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zzAS() throws SecurityException {
        int callingUid = Binder.getCallingUid();
        if (callingUid == this.zzZN) {
            return;
        }
        if (!GooglePlayServicesUtil.zzd(this, callingUid)) {
            throw new SecurityException("Caller is not GooglePlayServices");
        }
        this.zzZN = callingUid;
    }

    @Override // android.app.Service
    public final IBinder onBind(Intent intent) {
        if (BIND_LISTENER_INTENT_ACTION.equals(intent.getAction())) {
            return this.zzZQ;
        }
        return null;
    }

    @Override // com.google.android.gms.wearable.CapabilityApi.CapabilityListener
    public void onCapabilityChanged(CapabilityInfo capabilityInfo) {
    }

    @Override // com.google.android.gms.wearable.ChannelApi.ChannelListener
    public void onChannelClosed(Channel channel, int closeReason, int appSpecificErrorCode) {
    }

    @Override // com.google.android.gms.wearable.ChannelApi.ChannelListener
    public void onChannelOpened(Channel channel) {
    }

    @Override // com.google.android.gms.wearable.NodeApi.zza
    public void onConnectedNodes(List<Node> connectedNodes) {
    }

    @Override // android.app.Service
    public void onCreate() {
        super.onCreate();
        if (Log.isLoggable("WearableLS", 3)) {
            Log.d("WearableLS", "onCreate: " + getPackageName());
        }
        this.zzMZ = getPackageName();
        HandlerThread handlerThread = new HandlerThread("WearableListenerService");
        handlerThread.start();
        this.zzaTd = new Handler(handlerThread.getLooper());
        this.zzZQ = new zza();
    }

    @Override // com.google.android.gms.wearable.DataApi.DataListener
    public void onDataChanged(DataEventBuffer dataEvents) {
    }

    @Override // android.app.Service
    public void onDestroy() {
        synchronized (this.zzaTe) {
            this.zzJA = true;
            if (this.zzaTd == null) {
                throw new IllegalStateException("onDestroy: mServiceHandler not set, did you override onCreate() but forget to call super.onCreate()?");
            }
            this.zzaTd.getLooper().quit();
        }
        super.onDestroy();
    }

    @Override // com.google.android.gms.wearable.ChannelApi.ChannelListener
    public void onInputClosed(Channel channel, int closeReason, int appSpecificErrorCode) {
    }

    @Override // com.google.android.gms.wearable.MessageApi.MessageListener
    public void onMessageReceived(MessageEvent messageEvent) {
    }

    @Override // com.google.android.gms.wearable.ChannelApi.ChannelListener
    public void onOutputClosed(Channel channel, int closeReason, int appSpecificErrorCode) {
    }

    @Override // com.google.android.gms.wearable.NodeApi.NodeListener
    public void onPeerConnected(Node peer) {
    }

    @Override // com.google.android.gms.wearable.NodeApi.NodeListener
    public void onPeerDisconnected(Node peer) {
    }
}
