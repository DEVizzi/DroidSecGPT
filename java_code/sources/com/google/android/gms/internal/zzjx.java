package com.google.android.gms.internal;

import com.google.android.gms.cast.games.PlayerInfo;
import org.json.JSONObject;
/* loaded from: classes.dex */
public final class zzjx implements PlayerInfo {
    private final int zzSd;
    private final String zzTL;
    private final JSONObject zzUb;
    private final boolean zzUc;

    public zzjx(String str, int i, JSONObject jSONObject, boolean z) {
        this.zzTL = str;
        this.zzSd = i;
        this.zzUb = jSONObject;
        this.zzUc = z;
    }

    public boolean equals(Object otherObj) {
        if (otherObj == null || !(otherObj instanceof PlayerInfo)) {
            return false;
        }
        PlayerInfo playerInfo = (PlayerInfo) otherObj;
        return this.zzUc == playerInfo.isControllable() && this.zzSd == playerInfo.getPlayerState() && com.google.android.gms.cast.internal.zzf.zza(this.zzTL, playerInfo.getPlayerId()) && zzlh.zzd(this.zzUb, playerInfo.getPlayerData());
    }

    @Override // com.google.android.gms.cast.games.PlayerInfo
    public JSONObject getPlayerData() {
        return this.zzUb;
    }

    @Override // com.google.android.gms.cast.games.PlayerInfo
    public String getPlayerId() {
        return this.zzTL;
    }

    @Override // com.google.android.gms.cast.games.PlayerInfo
    public int getPlayerState() {
        return this.zzSd;
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(this.zzTL, Integer.valueOf(this.zzSd), this.zzUb, Boolean.valueOf(this.zzUc));
    }

    @Override // com.google.android.gms.cast.games.PlayerInfo
    public boolean isConnected() {
        switch (this.zzSd) {
            case 3:
            case 4:
            case 5:
            case 6:
                return true;
            default:
                return false;
        }
    }

    @Override // com.google.android.gms.cast.games.PlayerInfo
    public boolean isControllable() {
        return this.zzUc;
    }
}
