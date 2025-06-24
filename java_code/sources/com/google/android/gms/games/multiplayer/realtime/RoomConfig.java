package com.google.android.gms.games.multiplayer.realtime;

import android.os.Bundle;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.games.multiplayer.Multiplayer;
import java.util.ArrayList;
import java.util.Arrays;
/* loaded from: classes.dex */
public abstract class RoomConfig {

    /* loaded from: classes.dex */
    public static final class Builder {
        int zzaui;
        final RoomUpdateListener zzaut;
        RoomStatusUpdateListener zzauu;
        RealTimeMessageReceivedListener zzauv;
        String zzauw;
        ArrayList<String> zzaux;
        Bundle zzauy;

        private Builder(RoomUpdateListener updateListener) {
            this.zzauw = null;
            this.zzaui = -1;
            this.zzaux = new ArrayList<>();
            this.zzaut = (RoomUpdateListener) zzu.zzb(updateListener, "Must provide a RoomUpdateListener");
        }

        public Builder addPlayersToInvite(ArrayList<String> playerIds) {
            zzu.zzu(playerIds);
            this.zzaux.addAll(playerIds);
            return this;
        }

        public Builder addPlayersToInvite(String... playerIds) {
            zzu.zzu(playerIds);
            this.zzaux.addAll(Arrays.asList(playerIds));
            return this;
        }

        public RoomConfig build() {
            return new RoomConfigImpl(this);
        }

        public Builder setAutoMatchCriteria(Bundle autoMatchCriteria) {
            this.zzauy = autoMatchCriteria;
            return this;
        }

        public Builder setInvitationIdToAccept(String invitationId) {
            zzu.zzu(invitationId);
            this.zzauw = invitationId;
            return this;
        }

        public Builder setMessageReceivedListener(RealTimeMessageReceivedListener listener) {
            this.zzauv = listener;
            return this;
        }

        public Builder setRoomStatusUpdateListener(RoomStatusUpdateListener listener) {
            this.zzauu = listener;
            return this;
        }

        public Builder setVariant(int variant) {
            zzu.zzb(variant == -1 || variant > 0, "Variant must be a positive integer or Room.ROOM_VARIANT_ANY");
            this.zzaui = variant;
            return this;
        }
    }

    public static Builder builder(RoomUpdateListener listener) {
        return new Builder(listener);
    }

    public static Bundle createAutoMatchCriteria(int minAutoMatchPlayers, int maxAutoMatchPlayers, long exclusiveBitMask) {
        Bundle bundle = new Bundle();
        bundle.putInt(Multiplayer.EXTRA_MIN_AUTOMATCH_PLAYERS, minAutoMatchPlayers);
        bundle.putInt(Multiplayer.EXTRA_MAX_AUTOMATCH_PLAYERS, maxAutoMatchPlayers);
        bundle.putLong(Multiplayer.EXTRA_EXCLUSIVE_BIT_MASK, exclusiveBitMask);
        return bundle;
    }

    public abstract Bundle getAutoMatchCriteria();

    public abstract String getInvitationId();

    public abstract String[] getInvitedPlayerIds();

    public abstract RealTimeMessageReceivedListener getMessageReceivedListener();

    public abstract RoomStatusUpdateListener getRoomStatusUpdateListener();

    public abstract RoomUpdateListener getRoomUpdateListener();

    public abstract int getVariant();
}
