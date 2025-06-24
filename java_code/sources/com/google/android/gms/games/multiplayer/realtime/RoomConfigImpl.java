package com.google.android.gms.games.multiplayer.realtime;

import android.os.Bundle;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.games.multiplayer.realtime.RoomConfig;
/* loaded from: classes.dex */
public final class RoomConfigImpl extends RoomConfig {
    private final String zzapl;
    private final int zzaui;
    private final RoomUpdateListener zzaut;
    private final RoomStatusUpdateListener zzauu;
    private final RealTimeMessageReceivedListener zzauv;
    private final Bundle zzauy;
    private final String[] zzauz;

    /* JADX INFO: Access modifiers changed from: package-private */
    public RoomConfigImpl(RoomConfig.Builder builder) {
        this.zzaut = builder.zzaut;
        this.zzauu = builder.zzauu;
        this.zzauv = builder.zzauv;
        this.zzapl = builder.zzauw;
        this.zzaui = builder.zzaui;
        this.zzauy = builder.zzauy;
        this.zzauz = (String[]) builder.zzaux.toArray(new String[builder.zzaux.size()]);
        zzu.zzb(this.zzauv, "Must specify a message listener");
    }

    @Override // com.google.android.gms.games.multiplayer.realtime.RoomConfig
    public Bundle getAutoMatchCriteria() {
        return this.zzauy;
    }

    @Override // com.google.android.gms.games.multiplayer.realtime.RoomConfig
    public String getInvitationId() {
        return this.zzapl;
    }

    @Override // com.google.android.gms.games.multiplayer.realtime.RoomConfig
    public String[] getInvitedPlayerIds() {
        return this.zzauz;
    }

    @Override // com.google.android.gms.games.multiplayer.realtime.RoomConfig
    public RealTimeMessageReceivedListener getMessageReceivedListener() {
        return this.zzauv;
    }

    @Override // com.google.android.gms.games.multiplayer.realtime.RoomConfig
    public RoomStatusUpdateListener getRoomStatusUpdateListener() {
        return this.zzauu;
    }

    @Override // com.google.android.gms.games.multiplayer.realtime.RoomConfig
    public RoomUpdateListener getRoomUpdateListener() {
        return this.zzaut;
    }

    @Override // com.google.android.gms.games.multiplayer.realtime.RoomConfig
    public int getVariant() {
        return this.zzaui;
    }
}
