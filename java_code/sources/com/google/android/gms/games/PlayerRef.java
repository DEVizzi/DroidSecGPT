package com.google.android.gms.games;

import android.database.CharArrayBuffer;
import android.net.Uri;
import android.os.Parcel;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.data.zzc;
import com.google.android.gms.games.internal.player.MostRecentGameInfo;
import com.google.android.gms.games.internal.player.MostRecentGameInfoRef;
import com.google.android.gms.games.internal.player.PlayerColumnNames;
/* loaded from: classes.dex */
public final class PlayerRef extends zzc implements Player {
    private final PlayerLevelInfo zzanN;
    private final PlayerColumnNames zzanX;
    private final MostRecentGameInfoRef zzanY;

    public PlayerRef(DataHolder holder, int dataRow) {
        this(holder, dataRow, null);
    }

    public PlayerRef(DataHolder holder, int dataRow, String prefix) {
        super(holder, dataRow);
        this.zzanX = new PlayerColumnNames(prefix);
        this.zzanY = new MostRecentGameInfoRef(holder, dataRow, this.zzanX);
        if (!zzrM()) {
            this.zzanN = null;
            return;
        }
        int integer = getInteger(this.zzanX.zzatf);
        int integer2 = getInteger(this.zzanX.zzati);
        PlayerLevel playerLevel = new PlayerLevel(integer, getLong(this.zzanX.zzatg), getLong(this.zzanX.zzath));
        this.zzanN = new PlayerLevelInfo(getLong(this.zzanX.zzate), getLong(this.zzanX.zzatk), playerLevel, integer != integer2 ? new PlayerLevel(integer2, getLong(this.zzanX.zzath), getLong(this.zzanX.zzatj)) : playerLevel);
    }

    private boolean zzrM() {
        return (zzbX(this.zzanX.zzate) || getLong(this.zzanX.zzate) == -1) ? false : true;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // com.google.android.gms.common.data.zzc
    public boolean equals(Object obj) {
        return PlayerEntity.zza(this, obj);
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.google.android.gms.common.data.Freezable
    public Player freeze() {
        return new PlayerEntity(this);
    }

    @Override // com.google.android.gms.games.Player
    public String getDisplayName() {
        return getString(this.zzanX.zzasW);
    }

    @Override // com.google.android.gms.games.Player
    public void getDisplayName(CharArrayBuffer dataOut) {
        zza(this.zzanX.zzasW, dataOut);
    }

    @Override // com.google.android.gms.games.Player
    public Uri getHiResImageUri() {
        return zzbW(this.zzanX.zzasZ);
    }

    @Override // com.google.android.gms.games.Player
    public String getHiResImageUrl() {
        return getString(this.zzanX.zzata);
    }

    @Override // com.google.android.gms.games.Player
    public Uri getIconImageUri() {
        return zzbW(this.zzanX.zzasX);
    }

    @Override // com.google.android.gms.games.Player
    public String getIconImageUrl() {
        return getString(this.zzanX.zzasY);
    }

    @Override // com.google.android.gms.games.Player
    public long getLastPlayedWithTimestamp() {
        if (!zzbV(this.zzanX.zzatd) || zzbX(this.zzanX.zzatd)) {
            return -1L;
        }
        return getLong(this.zzanX.zzatd);
    }

    @Override // com.google.android.gms.games.Player
    public PlayerLevelInfo getLevelInfo() {
        return this.zzanN;
    }

    @Override // com.google.android.gms.games.Player
    public String getPlayerId() {
        return getString(this.zzanX.zzasV);
    }

    @Override // com.google.android.gms.games.Player
    public long getRetrievedTimestamp() {
        return getLong(this.zzanX.zzatb);
    }

    @Override // com.google.android.gms.games.Player
    public String getTitle() {
        return getString(this.zzanX.zzatl);
    }

    @Override // com.google.android.gms.games.Player
    public void getTitle(CharArrayBuffer dataOut) {
        zza(this.zzanX.zzatl, dataOut);
    }

    @Override // com.google.android.gms.games.Player
    public boolean hasHiResImage() {
        return getHiResImageUri() != null;
    }

    @Override // com.google.android.gms.games.Player
    public boolean hasIconImage() {
        return getIconImageUri() != null;
    }

    @Override // com.google.android.gms.common.data.zzc
    public int hashCode() {
        return PlayerEntity.zzb(this);
    }

    @Override // com.google.android.gms.games.Player
    public boolean isProfileVisible() {
        return getBoolean(this.zzanX.zzatn);
    }

    public String toString() {
        return PlayerEntity.zzc(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        ((PlayerEntity) freeze()).writeToParcel(dest, flags);
    }

    @Override // com.google.android.gms.games.Player
    public boolean zzrJ() {
        return getBoolean(this.zzanX.zzatu);
    }

    @Override // com.google.android.gms.games.Player
    public int zzrK() {
        return getInteger(this.zzanX.zzatc);
    }

    @Override // com.google.android.gms.games.Player
    public MostRecentGameInfo zzrL() {
        if (zzbX(this.zzanX.zzato)) {
            return null;
        }
        return this.zzanY;
    }
}
