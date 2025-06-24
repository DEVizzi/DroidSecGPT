package com.google.android.gms.games;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.common.internal.zzu;
/* loaded from: classes.dex */
public final class PlayerLevel implements SafeParcelable {
    public static final Parcelable.Creator<PlayerLevel> CREATOR = new PlayerLevelCreator();
    private final int zzCY;
    private final int zzanQ;
    private final long zzanR;
    private final long zzanS;

    /* JADX INFO: Access modifiers changed from: package-private */
    public PlayerLevel(int versionCode, int levelNumber, long minXp, long maxXp) {
        zzu.zza(minXp >= 0, "Min XP must be positive!");
        zzu.zza(maxXp > minXp, "Max XP must be more than min XP!");
        this.zzCY = versionCode;
        this.zzanQ = levelNumber;
        this.zzanR = minXp;
        this.zzanS = maxXp;
    }

    public PlayerLevel(int value, long minXp, long maxXp) {
        this(1, value, minXp, maxXp);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object obj) {
        if (obj instanceof PlayerLevel) {
            if (this != obj) {
                PlayerLevel playerLevel = (PlayerLevel) obj;
                return zzt.equal(Integer.valueOf(playerLevel.getLevelNumber()), Integer.valueOf(getLevelNumber())) && zzt.equal(Long.valueOf(playerLevel.getMinXp()), Long.valueOf(getMinXp())) && zzt.equal(Long.valueOf(playerLevel.getMaxXp()), Long.valueOf(getMaxXp()));
            }
            return true;
        }
        return false;
    }

    public int getLevelNumber() {
        return this.zzanQ;
    }

    public long getMaxXp() {
        return this.zzanS;
    }

    public long getMinXp() {
        return this.zzanR;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return zzt.hashCode(Integer.valueOf(this.zzanQ), Long.valueOf(this.zzanR), Long.valueOf(this.zzanS));
    }

    public String toString() {
        return zzt.zzt(this).zzg("LevelNumber", Integer.valueOf(getLevelNumber())).zzg("MinXp", Long.valueOf(getMinXp())).zzg("MaxXp", Long.valueOf(getMaxXp())).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        PlayerLevelCreator.zza(this, out, flags);
    }
}
