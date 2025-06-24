package com.google.android.gms.internal;

import com.google.android.gms.games.Games;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
/* loaded from: classes.dex */
public class zzju {
    private static final com.google.android.gms.cast.internal.zzl zzQW = new com.google.android.gms.cast.internal.zzl("GameManagerMessage");
    protected final String zzTL;
    protected final long zzTM;
    protected final JSONObject zzTN;
    protected final int zzTR;
    protected final int zzTS;
    protected final String zzTT;
    protected final int zzTU;
    protected final int zzTV;
    protected final List<zzjy> zzTW;
    protected final JSONObject zzTX;
    protected final String zzTY;
    protected final String zzTZ;
    protected final zzjt zzTs;

    public zzju(int i, int i2, String str, JSONObject jSONObject, int i3, int i4, List<zzjy> list, JSONObject jSONObject2, String str2, String str3, long j, String str4, zzjt zzjtVar) {
        this.zzTR = i;
        this.zzTS = i2;
        this.zzTT = str;
        this.zzTN = jSONObject;
        this.zzTU = i3;
        this.zzTV = i4;
        this.zzTW = list;
        this.zzTX = jSONObject2;
        this.zzTY = str2;
        this.zzTL = str3;
        this.zzTM = j;
        this.zzTZ = str4;
        this.zzTs = zzjtVar;
    }

    private static List<zzjy> zza(JSONArray jSONArray) {
        zzjy zzjyVar;
        ArrayList arrayList = new ArrayList();
        if (jSONArray == null) {
            return arrayList;
        }
        for (int i = 0; i < jSONArray.length(); i++) {
            JSONObject optJSONObject = jSONArray.optJSONObject(i);
            if (optJSONObject != null) {
                try {
                    zzjyVar = new zzjy(optJSONObject);
                } catch (JSONException e) {
                    zzQW.zzc(e, "Exception when attempting to parse PlayerInfoMessageComponent at index %d", Integer.valueOf(i));
                    zzjyVar = null;
                }
                if (zzjyVar != null) {
                    arrayList.add(zzjyVar);
                }
            }
        }
        return arrayList;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static zzju zzh(JSONObject jSONObject) {
        int optInt = jSONObject.optInt("type", -1);
        try {
        } catch (JSONException e) {
            zzQW.zzc(e, "Exception while parsing GameManagerMessage from json", new Object[0]);
        }
        switch (optInt) {
            case 1:
                JSONObject optJSONObject = jSONObject.optJSONObject("gameManagerConfig");
                return new zzju(optInt, jSONObject.optInt("statusCode"), jSONObject.optString("errorDescription"), jSONObject.optJSONObject("extraMessageData"), jSONObject.optInt("gameplayState"), jSONObject.optInt("lobbyState"), zza(jSONObject.optJSONArray(Games.EXTRA_PLAYER_IDS)), jSONObject.optJSONObject("gameData"), jSONObject.optString("gameStatusText"), jSONObject.optString("playerId"), jSONObject.optLong("requestId"), jSONObject.optString("playerToken"), optJSONObject != null ? new zzjt(optJSONObject) : null);
            case 2:
                return new zzju(optInt, jSONObject.optInt("statusCode"), jSONObject.optString("errorDescription"), jSONObject.optJSONObject("extraMessageData"), jSONObject.optInt("gameplayState"), jSONObject.optInt("lobbyState"), zza(jSONObject.optJSONArray(Games.EXTRA_PLAYER_IDS)), jSONObject.optJSONObject("gameData"), jSONObject.optString("gameStatusText"), jSONObject.optString("playerId"), -1L, null, null);
            default:
                zzQW.zzf("Unrecognized Game Message type %d", Integer.valueOf(optInt));
                return null;
        }
    }

    public final JSONObject getExtraMessageData() {
        return this.zzTN;
    }

    public final JSONObject getGameData() {
        return this.zzTX;
    }

    public final int getGameplayState() {
        return this.zzTU;
    }

    public final int getLobbyState() {
        return this.zzTV;
    }

    public final String getPlayerId() {
        return this.zzTL;
    }

    public final long getRequestId() {
        return this.zzTM;
    }

    public final int getStatusCode() {
        return this.zzTS;
    }

    public final int zzlC() {
        return this.zzTR;
    }

    public final String zzlD() {
        return this.zzTT;
    }

    public final List<zzjy> zzlE() {
        return this.zzTW;
    }

    public final String zzlF() {
        return this.zzTY;
    }

    public final String zzlG() {
        return this.zzTZ;
    }

    public final zzjt zzlH() {
        return this.zzTs;
    }
}
