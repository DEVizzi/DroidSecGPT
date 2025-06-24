package com.google.android.gms.games.internal.request;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzb;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.games.Game;
import com.google.android.gms.games.Player;
import com.google.android.gms.games.request.GameRequest;
import com.google.android.gms.games.request.GameRequestEntity;
import java.util.ArrayList;
/* loaded from: classes.dex */
public final class GameRequestCluster implements SafeParcelable, GameRequest {
    public static final GameRequestClusterCreator CREATOR = new GameRequestClusterCreator();
    private final int zzCY;
    private final ArrayList<GameRequestEntity> zzatv;

    /* JADX INFO: Access modifiers changed from: package-private */
    public GameRequestCluster(int versionCode, ArrayList<GameRequestEntity> requestList) {
        this.zzCY = versionCode;
        this.zzatv = requestList;
        zztn();
    }

    private void zztn() {
        zzb.zzU(!this.zzatv.isEmpty());
        GameRequestEntity gameRequestEntity = this.zzatv.get(0);
        int size = this.zzatv.size();
        for (int i = 1; i < size; i++) {
            GameRequestEntity gameRequestEntity2 = this.zzatv.get(i);
            zzb.zza(gameRequestEntity.getType() == gameRequestEntity2.getType(), "All the requests must be of the same type");
            zzb.zza(gameRequestEntity.getSender().equals(gameRequestEntity2.getSender()), "All the requests must be from the same sender");
        }
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object obj) {
        if (obj instanceof GameRequestCluster) {
            if (this == obj) {
                return true;
            }
            GameRequestCluster gameRequestCluster = (GameRequestCluster) obj;
            if (gameRequestCluster.zzatv.size() != this.zzatv.size()) {
                return false;
            }
            int size = this.zzatv.size();
            for (int i = 0; i < size; i++) {
                if (!this.zzatv.get(i).equals(gameRequestCluster.zzatv.get(i))) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.google.android.gms.common.data.Freezable
    public GameRequest freeze() {
        return this;
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public long getCreationTimestamp() {
        throw new UnsupportedOperationException("Method not supported on a cluster");
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public byte[] getData() {
        throw new UnsupportedOperationException("Method not supported on a cluster");
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public long getExpirationTimestamp() {
        throw new UnsupportedOperationException("Method not supported on a cluster");
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public Game getGame() {
        throw new UnsupportedOperationException("Method not supported on a cluster");
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public int getRecipientStatus(String playerId) {
        throw new UnsupportedOperationException("Method not supported on a cluster");
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public String getRequestId() {
        return this.zzatv.get(0).getRequestId();
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public Player getSender() {
        return this.zzatv.get(0).getSender();
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public int getStatus() {
        throw new UnsupportedOperationException("Method not supported on a cluster");
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public int getType() {
        return this.zzatv.get(0).getType();
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return zzt.hashCode(this.zzatv.toArray());
    }

    @Override // com.google.android.gms.games.request.GameRequest
    public boolean isConsumed(String playerId) {
        throw new UnsupportedOperationException("Method not supported on a cluster");
    }

    @Override // com.google.android.gms.common.data.Freezable
    public boolean isDataValid() {
        return true;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        GameRequestClusterCreator.zza(this, dest, flags);
    }

    public ArrayList<GameRequest> zztB() {
        return new ArrayList<>(this.zzatv);
    }

    @Override // com.google.android.gms.games.request.GameRequest
    /* renamed from: zztC */
    public ArrayList<Player> getRecipients() {
        throw new UnsupportedOperationException("Method not supported on a cluster");
    }
}
