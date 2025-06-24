package com.google.android.gms.wearable.internal;

import com.google.android.gms.wearable.Channel;
import com.google.android.gms.wearable.ChannelApi;
/* loaded from: classes.dex */
final class zzbf implements ChannelApi.ChannelListener {
    private final String zzaTK;
    private final ChannelApi.ChannelListener zzaUO;

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzbf(String str, ChannelApi.ChannelListener channelListener) {
        this.zzaTK = (String) com.google.android.gms.common.internal.zzu.zzu(str);
        this.zzaUO = (ChannelApi.ChannelListener) com.google.android.gms.common.internal.zzu.zzu(channelListener);
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o instanceof zzbf) {
            zzbf zzbfVar = (zzbf) o;
            return this.zzaUO.equals(zzbfVar.zzaUO) && this.zzaTK.equals(zzbfVar.zzaTK);
        }
        return false;
    }

    public int hashCode() {
        return (this.zzaTK.hashCode() * 31) + this.zzaUO.hashCode();
    }

    @Override // com.google.android.gms.wearable.ChannelApi.ChannelListener
    public void onChannelClosed(Channel channel, int closeReason, int appSpecificErrorCode) {
        this.zzaUO.onChannelClosed(channel, closeReason, appSpecificErrorCode);
    }

    @Override // com.google.android.gms.wearable.ChannelApi.ChannelListener
    public void onChannelOpened(Channel channel) {
        this.zzaUO.onChannelOpened(channel);
    }

    @Override // com.google.android.gms.wearable.ChannelApi.ChannelListener
    public void onInputClosed(Channel channel, int closeReason, int appSpecificErrorCode) {
        this.zzaUO.onInputClosed(channel, closeReason, appSpecificErrorCode);
    }

    @Override // com.google.android.gms.wearable.ChannelApi.ChannelListener
    public void onOutputClosed(Channel channel, int closeReason, int appSpecificErrorCode) {
        this.zzaUO.onOutputClosed(channel, closeReason, appSpecificErrorCode);
    }
}
