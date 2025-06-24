package com.google.android.gms.games.multiplayer.turnbased;

import android.os.Bundle;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.games.multiplayer.Multiplayer;
import java.util.ArrayList;
/* loaded from: classes.dex */
public abstract class TurnBasedMatchConfig {

    /* loaded from: classes.dex */
    public static final class Builder {
        int zzauH;
        int zzaui;
        ArrayList<String> zzaux;
        Bundle zzauy;

        private Builder() {
            this.zzaui = -1;
            this.zzaux = new ArrayList<>();
            this.zzauy = null;
            this.zzauH = 2;
        }

        public Builder addInvitedPlayer(String playerId) {
            zzu.zzu(playerId);
            this.zzaux.add(playerId);
            return this;
        }

        public Builder addInvitedPlayers(ArrayList<String> playerIds) {
            zzu.zzu(playerIds);
            this.zzaux.addAll(playerIds);
            return this;
        }

        public TurnBasedMatchConfig build() {
            return new TurnBasedMatchConfigImpl(this);
        }

        public Builder setAutoMatchCriteria(Bundle autoMatchCriteria) {
            this.zzauy = autoMatchCriteria;
            return this;
        }

        public Builder setVariant(int variant) {
            zzu.zzb(variant == -1 || variant > 0, "Variant must be a positive integer or TurnBasedMatch.MATCH_VARIANT_ANY");
            this.zzaui = variant;
            return this;
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Bundle createAutoMatchCriteria(int minAutoMatchPlayers, int maxAutoMatchPlayers, long exclusiveBitMask) {
        Bundle bundle = new Bundle();
        bundle.putInt(Multiplayer.EXTRA_MIN_AUTOMATCH_PLAYERS, minAutoMatchPlayers);
        bundle.putInt(Multiplayer.EXTRA_MAX_AUTOMATCH_PLAYERS, maxAutoMatchPlayers);
        bundle.putLong(Multiplayer.EXTRA_EXCLUSIVE_BIT_MASK, exclusiveBitMask);
        return bundle;
    }

    public abstract Bundle getAutoMatchCriteria();

    public abstract String[] getInvitedPlayerIds();

    public abstract int getVariant();

    public abstract int zztL();
}
