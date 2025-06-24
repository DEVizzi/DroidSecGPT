package com.google.android.gms.internal;

import com.google.android.gms.cast.games.GameManagerState;
import com.google.android.gms.cast.games.PlayerInfo;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;
/* loaded from: classes.dex */
public final class zzjw implements GameManagerState {
    private final String zzTO;
    private final int zzTP;
    private final int zzTU;
    private final int zzTV;
    private final JSONObject zzTX;
    private final String zzTY;
    private final Map<String, PlayerInfo> zzUa;

    public zzjw(int i, int i2, String str, JSONObject jSONObject, Collection<PlayerInfo> collection, String str2, int i3) {
        this.zzTV = i;
        this.zzTU = i2;
        this.zzTY = str;
        this.zzTX = jSONObject;
        this.zzTO = str2;
        this.zzTP = i3;
        this.zzUa = new HashMap(collection.size());
        for (PlayerInfo playerInfo : collection) {
            this.zzUa.put(playerInfo.getPlayerId(), playerInfo);
        }
    }

    public boolean equals(Object otherObj) {
        boolean z;
        boolean z2 = true;
        if (otherObj == null || !(otherObj instanceof GameManagerState)) {
            return false;
        }
        GameManagerState gameManagerState = (GameManagerState) otherObj;
        if (getPlayers().size() == gameManagerState.getPlayers().size()) {
            for (PlayerInfo playerInfo : getPlayers()) {
                boolean z3 = false;
                for (PlayerInfo playerInfo2 : gameManagerState.getPlayers()) {
                    if (!com.google.android.gms.cast.internal.zzf.zza(playerInfo.getPlayerId(), playerInfo2.getPlayerId())) {
                        z = z3;
                    } else if (!com.google.android.gms.cast.internal.zzf.zza(playerInfo, playerInfo2)) {
                        return false;
                    } else {
                        z = true;
                    }
                    z3 = z;
                }
                if (!z3) {
                    return false;
                }
            }
            return (this.zzTV == gameManagerState.getLobbyState() && this.zzTU == gameManagerState.getGameplayState() && this.zzTP == gameManagerState.getMaxPlayers() && com.google.android.gms.cast.internal.zzf.zza(this.zzTO, gameManagerState.getApplicationName()) && com.google.android.gms.cast.internal.zzf.zza(this.zzTY, gameManagerState.getGameStatusText()) && zzlh.zzd(this.zzTX, gameManagerState.getGameData())) ? false : false;
        }
        return false;
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public CharSequence getApplicationName() {
        return this.zzTO;
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public List<PlayerInfo> getConnectedControllablePlayers() {
        ArrayList arrayList = new ArrayList();
        for (PlayerInfo playerInfo : getPlayers()) {
            if (playerInfo.isConnected() && playerInfo.isControllable()) {
                arrayList.add(playerInfo);
            }
        }
        return arrayList;
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public List<PlayerInfo> getConnectedPlayers() {
        ArrayList arrayList = new ArrayList();
        for (PlayerInfo playerInfo : getPlayers()) {
            if (playerInfo.isConnected()) {
                arrayList.add(playerInfo);
            }
        }
        return arrayList;
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public List<PlayerInfo> getControllablePlayers() {
        ArrayList arrayList = new ArrayList();
        for (PlayerInfo playerInfo : getPlayers()) {
            if (playerInfo.isControllable()) {
                arrayList.add(playerInfo);
            }
        }
        return arrayList;
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public JSONObject getGameData() {
        return this.zzTX;
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public CharSequence getGameStatusText() {
        return this.zzTY;
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public int getGameplayState() {
        return this.zzTU;
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public Collection<String> getListOfChangedPlayers(GameManagerState other) {
        HashSet hashSet = new HashSet();
        for (PlayerInfo playerInfo : getPlayers()) {
            PlayerInfo player = other.getPlayer(playerInfo.getPlayerId());
            if (player == null || !playerInfo.equals(player)) {
                hashSet.add(playerInfo.getPlayerId());
            }
        }
        for (PlayerInfo playerInfo2 : other.getPlayers()) {
            if (getPlayer(playerInfo2.getPlayerId()) == null) {
                hashSet.add(playerInfo2.getPlayerId());
            }
        }
        return hashSet;
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public int getLobbyState() {
        return this.zzTV;
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public int getMaxPlayers() {
        return this.zzTP;
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public PlayerInfo getPlayer(String playerId) {
        if (playerId == null) {
            return null;
        }
        return this.zzUa.get(playerId);
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public Collection<PlayerInfo> getPlayers() {
        return Collections.unmodifiableCollection(this.zzUa.values());
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public List<PlayerInfo> getPlayersInState(int playerState) {
        ArrayList arrayList = new ArrayList();
        for (PlayerInfo playerInfo : getPlayers()) {
            if (playerInfo.getPlayerState() == playerState) {
                arrayList.add(playerInfo);
            }
        }
        return arrayList;
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public boolean hasGameDataChanged(GameManagerState other) {
        return !zzlh.zzd(this.zzTX, other.getGameData());
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public boolean hasGameStatusTextChanged(GameManagerState other) {
        return !com.google.android.gms.cast.internal.zzf.zza(this.zzTY, other.getGameStatusText());
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public boolean hasGameplayStateChanged(GameManagerState other) {
        return this.zzTU != other.getGameplayState();
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public boolean hasLobbyStateChanged(GameManagerState other) {
        return this.zzTV != other.getLobbyState();
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public boolean hasPlayerChanged(String playerId, GameManagerState other) {
        return !com.google.android.gms.cast.internal.zzf.zza(getPlayer(playerId), other.getPlayer(playerId));
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public boolean hasPlayerDataChanged(String playerId, GameManagerState other) {
        PlayerInfo player = getPlayer(playerId);
        PlayerInfo player2 = other.getPlayer(playerId);
        if (player == null && player2 == null) {
            return false;
        }
        return player == null || player2 == null || !zzlh.zzd(player.getPlayerData(), player2.getPlayerData());
    }

    @Override // com.google.android.gms.cast.games.GameManagerState
    public boolean hasPlayerStateChanged(String playerId, GameManagerState other) {
        PlayerInfo player = getPlayer(playerId);
        PlayerInfo player2 = other.getPlayer(playerId);
        if (player == null && player2 == null) {
            return false;
        }
        return player == null || player2 == null || player.getPlayerState() != player2.getPlayerState();
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(Integer.valueOf(this.zzTV), Integer.valueOf(this.zzTU), this.zzUa, this.zzTY, this.zzTX, this.zzTO, Integer.valueOf(this.zzTP));
    }
}
