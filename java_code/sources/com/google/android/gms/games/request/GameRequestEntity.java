package com.google.android.gms.games.request;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.games.Game;
import com.google.android.gms.games.GameEntity;
import com.google.android.gms.games.Player;
import com.google.android.gms.games.PlayerEntity;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
/* loaded from: classes.dex */
public final class GameRequestEntity implements SafeParcelable, GameRequest {
    public static final Parcelable.Creator<GameRequestEntity> CREATOR = new GameRequestEntityCreator();
    private final int zzCY;
    private final String zzDK;
    private final int zzSq;
    private final byte[] zzauL;
    private final GameEntity zzaud;
    private final long zzaue;
    private final PlayerEntity zzavf;
    private final ArrayList<PlayerEntity> zzavg;
    private final long zzavh;
    private final Bundle zzavi;
    private final int zzwS;

    /* JADX INFO: Access modifiers changed from: package-private */
    public GameRequestEntity(int versionCode, GameEntity game, PlayerEntity sender, byte[] data, String requestId, ArrayList<PlayerEntity> recipients, int type, long creationTimestamp, long expirationTimestamp, Bundle recipientStatuses, int status) {
        this.zzCY = versionCode;
        this.zzaud = game;
        this.zzavf = sender;
        this.zzauL = data;
        this.zzDK = requestId;
        this.zzavg = recipients;
        this.zzSq = type;
        this.zzaue = creationTimestamp;
        this.zzavh = expirationTimestamp;
        this.zzavi = recipientStatuses;
        this.zzwS = status;
    }

    public GameRequestEntity(GameRequest request) {
        this.zzCY = 2;
        this.zzaud = new GameEntity(request.getGame());
        this.zzavf = new PlayerEntity(request.getSender());
        this.zzDK = request.getRequestId();
        this.zzSq = request.getType();
        this.zzaue = request.getCreationTimestamp();
        this.zzavh = request.getExpirationTimestamp();
        this.zzwS = request.getStatus();
        byte[] data = request.getData();
        if (data == null) {
            this.zzauL = null;
        } else {
            this.zzauL = new byte[data.length];
            System.arraycopy(data, 0, this.zzauL, 0, data.length);
        }
        List<Player> recipients = request.getRecipients();
        int size = recipients.size();
        this.zzavg = new ArrayList<>(size);
        this.zzavi = new Bundle();
        for (int i = 0; i < size; i++) {
            Player freeze = recipients.get(i).freeze();
            String playerId = freeze.getPlayerId();
            this.zzavg.add((PlayerEntity) freeze);
            this.zzavi.putInt(playerId, request.getRecipientStatus(playerId));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int zza(GameRequest gameRequest) {
        return zzt.hashCode(gameRequest.getGame(), gameRequest.getRecipients(), gameRequest.getRequestId(), gameRequest.getSender(), zzb(gameRequest), Integer.valueOf(gameRequest.getType()), Long.valueOf(gameRequest.getCreationTimestamp()), Long.valueOf(gameRequest.getExpirationTimestamp()));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean zza(GameRequest gameRequest, Object obj) {
        if (obj instanceof GameRequest) {
            if (gameRequest != obj) {
                GameRequest gameRequest2 = (GameRequest) obj;
                return zzt.equal(gameRequest2.getGame(), gameRequest.getGame()) && zzt.equal(gameRequest2.getRecipients(), gameRequest.getRecipients()) && zzt.equal(gameRequest2.getRequestId(), gameRequest.getRequestId()) && zzt.equal(gameRequest2.getSender(), gameRequest.getSender()) && Arrays.equals(zzb(gameRequest2), zzb(gameRequest)) && zzt.equal(Integer.valueOf(gameRequest2.getType()), Integer.valueOf(gameRequest.getType())) && zzt.equal(Long.valueOf(gameRequest2.getCreationTimestamp()), Long.valueOf(gameRequest.getCreationTimestamp())) && zzt.equal(Long.valueOf(gameRequest2.getExpirationTimestamp()), Long.valueOf(gameRequest.getExpirationTimestamp()));
            }
            return true;
        }
        return false;
    }

    private static int[] zzb(GameRequest gameRequest) {
        List<Player> recipients = gameRequest.getRecipients();
        int size = recipients.size();
        int[] iArr = new int[size];
        for (int i = 0; i < size; i++) {
            iArr[i] = gameRequest.getRecipientStatus(recipients.get(i).getPlayerId());
        }
        return iArr;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String zzc(GameRequest gameRequest) {
        return zzt.zzt(gameRequest).zzg("Game", gameRequest.getGame()).zzg("Sender", gameRequest.getSender()).zzg("Recipients", gameRequest.getRecipients()).zzg("Data", gameRequest.getData()).zzg("RequestId", gameRequest.getRequestId()).zzg("Type", Integer.valueOf(gameRequest.getType())).zzg("CreationTimestamp", Long.valueOf(gameRequest.getCreationTimestamp())).zzg("ExpirationTimestamp", Long.valueOf(gameRequest.getExpirationTimestamp())).toString();
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object obj) {
        return zza(this, obj);
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.google.android.gms.common.data.Freezable
    public GameRequest freeze() {
        return this;
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public long getCreationTimestamp() {
        return this.zzaue;
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public byte[] getData() {
        return this.zzauL;
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public long getExpirationTimestamp() {
        return this.zzavh;
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public Game getGame() {
        return this.zzaud;
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public int getRecipientStatus(String playerId) {
        return this.zzavi.getInt(playerId, 0);
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public List<Player> getRecipients() {
        return new ArrayList(this.zzavg);
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public String getRequestId() {
        return this.zzDK;
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public Player getSender() {
        return this.zzavf;
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public int getStatus() {
        return this.zzwS;
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public int getType() {
        return this.zzSq;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return zza(this);
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public boolean isConsumed(String playerId) {
        return getRecipientStatus(playerId) == 1;
    }

    @Override // com.google.android.gms.common.data.Freezable
    public boolean isDataValid() {
        return true;
    }

    public String toString() {
        return zzc(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        GameRequestEntityCreator.zza(this, dest, flags);
    }

    public Bundle zztP() {
        return this.zzavi;
    }
}
