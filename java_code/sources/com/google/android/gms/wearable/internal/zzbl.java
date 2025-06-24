package com.google.android.gms.wearable.internal;

import android.content.IntentFilter;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.wearable.CapabilityApi;
import com.google.android.gms.wearable.ChannelApi;
import com.google.android.gms.wearable.DataApi;
import com.google.android.gms.wearable.DataEventBuffer;
import com.google.android.gms.wearable.MessageApi;
import com.google.android.gms.wearable.NodeApi;
import com.google.android.gms.wearable.internal.zzas;
import com.google.android.gms.wearable.zza;
import java.util.List;
/* loaded from: classes.dex */
final class zzbl<T> extends zzas.zza {
    private final String zzaTD;
    private final IntentFilter[] zzaUk;
    private zza.InterfaceC0242zza zzaVb;
    private DataApi.DataListener zzaVc;
    private MessageApi.MessageListener zzaVd;
    private NodeApi.NodeListener zzaVe;
    private NodeApi.zza zzaVf;
    private ChannelApi.ChannelListener zzaVg;
    private CapabilityApi.CapabilityListener zzaVh;
    private final String zzaVi;

    private zzbl(zza.InterfaceC0242zza interfaceC0242zza, DataApi.DataListener dataListener, MessageApi.MessageListener messageListener, NodeApi.NodeListener nodeListener, NodeApi.zza zzaVar, ChannelApi.ChannelListener channelListener, CapabilityApi.CapabilityListener capabilityListener, IntentFilter[] intentFilterArr, String str, String str2) {
        this.zzaVb = interfaceC0242zza;
        this.zzaVc = dataListener;
        this.zzaVd = messageListener;
        this.zzaVe = nodeListener;
        this.zzaVf = zzaVar;
        this.zzaVg = channelListener;
        this.zzaVh = capabilityListener;
        this.zzaUk = intentFilterArr;
        this.zzaVi = str;
        this.zzaTD = str2;
    }

    public static zzbl<CapabilityApi.CapabilityListener> zza(CapabilityApi.CapabilityListener capabilityListener, String str) {
        return new zzbl<>(null, null, null, null, null, null, (CapabilityApi.CapabilityListener) com.google.android.gms.common.internal.zzu.zzu(capabilityListener), null, null, str);
    }

    public static zzbl<ChannelApi.ChannelListener> zza(ChannelApi.ChannelListener channelListener, String str) {
        return new zzbl<>(null, null, null, null, null, (ChannelApi.ChannelListener) com.google.android.gms.common.internal.zzu.zzu(channelListener), null, null, (String) com.google.android.gms.common.internal.zzu.zzu(str), null);
    }

    public static zzbl<DataApi.DataListener> zza(DataApi.DataListener dataListener, IntentFilter[] intentFilterArr) {
        return new zzbl<>(null, (DataApi.DataListener) com.google.android.gms.common.internal.zzu.zzu(dataListener), null, null, null, null, null, intentFilterArr, null, null);
    }

    public static zzbl<MessageApi.MessageListener> zza(MessageApi.MessageListener messageListener, IntentFilter[] intentFilterArr) {
        return new zzbl<>(null, null, (MessageApi.MessageListener) com.google.android.gms.common.internal.zzu.zzu(messageListener), null, null, null, null, intentFilterArr, null, null);
    }

    public static zzbl<NodeApi.NodeListener> zza(NodeApi.NodeListener nodeListener) {
        return new zzbl<>(null, null, null, (NodeApi.NodeListener) com.google.android.gms.common.internal.zzu.zzu(nodeListener), null, null, null, null, null, null);
    }

    public static zzbl<ChannelApi.ChannelListener> zzb(ChannelApi.ChannelListener channelListener) {
        return new zzbl<>(null, null, null, null, null, (ChannelApi.ChannelListener) com.google.android.gms.common.internal.zzu.zzu(channelListener), null, null, null, null);
    }

    public void clear() {
        this.zzaVb = null;
        this.zzaVc = null;
        this.zzaVd = null;
        this.zzaVe = null;
        this.zzaVf = null;
        this.zzaVg = null;
        this.zzaVh = null;
    }

    @Override // com.google.android.gms.wearable.internal.zzas
    public void onConnectedNodes(List<NodeParcelable> connectedNodes) {
        if (this.zzaVf != null) {
            this.zzaVf.onConnectedNodes(connectedNodes);
        }
    }

    public IntentFilter[] zzBh() {
        return this.zzaUk;
    }

    public String zzBi() {
        return this.zzaVi;
    }

    public String zzBj() {
        return this.zzaTD;
    }

    @Override // com.google.android.gms.wearable.internal.zzas
    public void zza(AncsNotificationParcelable ancsNotificationParcelable) {
        if (this.zzaVb != null) {
            this.zzaVb.zza(ancsNotificationParcelable);
        }
    }

    @Override // com.google.android.gms.wearable.internal.zzas
    public void zza(CapabilityInfoParcelable capabilityInfoParcelable) {
        if (this.zzaVh != null) {
            this.zzaVh.onCapabilityChanged(capabilityInfoParcelable);
        }
    }

    @Override // com.google.android.gms.wearable.internal.zzas
    public void zza(ChannelEventParcelable channelEventParcelable) {
        if (this.zzaVg != null) {
            channelEventParcelable.zza(this.zzaVg);
        }
    }

    @Override // com.google.android.gms.wearable.internal.zzas
    public void zza(MessageEventParcelable messageEventParcelable) {
        if (this.zzaVd != null) {
            this.zzaVd.onMessageReceived(messageEventParcelable);
        }
    }

    @Override // com.google.android.gms.wearable.internal.zzas
    public void zza(NodeParcelable nodeParcelable) {
        if (this.zzaVe != null) {
            this.zzaVe.onPeerConnected(nodeParcelable);
        }
    }

    @Override // com.google.android.gms.wearable.internal.zzas
    public void zzac(DataHolder dataHolder) {
        if (this.zzaVc != null) {
            try {
                this.zzaVc.onDataChanged(new DataEventBuffer(dataHolder));
            } finally {
                dataHolder.close();
            }
        }
    }

    @Override // com.google.android.gms.wearable.internal.zzas
    public void zzb(NodeParcelable nodeParcelable) {
        if (this.zzaVe != null) {
            this.zzaVe.onPeerDisconnected(nodeParcelable);
        }
    }
}
