package com.google.android.gms.games.multiplayer.turnbased;

import android.os.Bundle;
import com.google.android.gms.games.multiplayer.turnbased.TurnBasedMatchConfig;
/* loaded from: classes.dex */
public final class TurnBasedMatchConfigImpl extends TurnBasedMatchConfig {
    private final int zzauH;
    private final int zzaui;
    private final Bundle zzauy;
    private final String[] zzauz;

    /* JADX INFO: Access modifiers changed from: package-private */
    public TurnBasedMatchConfigImpl(TurnBasedMatchConfig.Builder builder) {
        this.zzaui = builder.zzaui;
        this.zzauH = builder.zzauH;
        this.zzauy = builder.zzauy;
        this.zzauz = (String[]) builder.zzaux.toArray(new String[builder.zzaux.size()]);
    }

    @Override // com.google.android.gms.games.multiplayer.turnbased.TurnBasedMatchConfig
    public Bundle getAutoMatchCriteria() {
        return this.zzauy;
    }

    @Override // com.google.android.gms.games.multiplayer.turnbased.TurnBasedMatchConfig
    public String[] getInvitedPlayerIds() {
        return this.zzauz;
    }

    @Override // com.google.android.gms.games.multiplayer.turnbased.TurnBasedMatchConfig
    public int getVariant() {
        return this.zzaui;
    }

    @Override // com.google.android.gms.games.multiplayer.turnbased.TurnBasedMatchConfig
    public int zztL() {
        return this.zzauH;
    }
}
