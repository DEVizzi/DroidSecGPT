package com.google.android.gms.games;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.common.internal.zzu;
/* loaded from: classes.dex */
public final class PlayerLevelInfo implements SafeParcelable {
    public static final Parcelable.Creator<PlayerLevelInfo> CREATOR = new PlayerLevelInfoCreator();
    private final int zzCY;
    private final long zzanT;
    private final long zzanU;
    private final PlayerLevel zzanV;
    private final PlayerLevel zzanW;

    /* JADX INFO: Access modifiers changed from: package-private */
    public PlayerLevelInfo(int versionCode, long currentXpTotal, long lastLevelUpTimestamp, PlayerLevel currentLevel, PlayerLevel nextLevel) {
        zzu.zzU(currentXpTotal != -1);
        zzu.zzu(currentLevel);
        zzu.zzu(nextLevel);
        this.zzCY = versionCode;
        this.zzanT = currentXpTotal;
        this.zzanU = lastLevelUpTimestamp;
        this.zzanV = currentLevel;
        this.zzanW = nextLevel;
    }

    public PlayerLevelInfo(long currentXpTotal, long lastLevelUpTimestamp, PlayerLevel currentLevel, PlayerLevel nextLevel) {
        this(1, currentXpTotal, lastLevelUpTimestamp, currentLevel, nextLevel);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object obj) {
        if (obj instanceof PlayerLevelInfo) {
            if (obj != this) {
                PlayerLevelInfo playerLevelInfo = (PlayerLevelInfo) obj;
                return zzt.equal(Long.valueOf(this.zzanT), Long.valueOf(playerLevelInfo.zzanT)) && zzt.equal(Long.valueOf(this.zzanU), Long.valueOf(playerLevelInfo.zzanU)) && zzt.equal(this.zzanV, playerLevelInfo.zzanV) && zzt.equal(this.zzanW, playerLevelInfo.zzanW);
            }
            return true;
        }
        return false;
    }

    public PlayerLevel getCurrentLevel() {
        return this.zzanV;
    }

    public long getCurrentXpTotal() {
        return this.zzanT;
    }

    public long getLastLevelUpTimestamp() {
        return this.zzanU;
    }

    public PlayerLevel getNextLevel() {
        return this.zzanW;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return zzt.hashCode(Long.valueOf(this.zzanT), Long.valueOf(this.zzanU), this.zzanV, this.zzanW);
    }

    public boolean isMaxLevel() {
        return this.zzanV.equals(this.zzanW);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        PlayerLevelInfoCreator.zza(this, out, flags);
    }
}
