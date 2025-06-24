package com.google.android.gms.games.internal.player;

import android.net.Uri;
import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
/* loaded from: classes.dex */
public final class MostRecentGameInfoEntity implements SafeParcelable, MostRecentGameInfo {
    public static final MostRecentGameInfoEntityCreator CREATOR = new MostRecentGameInfoEntityCreator();
    private final int zzCY;
    private final String zzasP;
    private final String zzasQ;
    private final long zzasR;
    private final Uri zzasS;
    private final Uri zzasT;
    private final Uri zzasU;

    /* JADX INFO: Access modifiers changed from: package-private */
    public MostRecentGameInfoEntity(int versionCode, String gameId, String gameName, long activityTimestampMillis, Uri gameIconImageUri, Uri gameHiResIconImageUri, Uri gameFeaturedImageUri) {
        this.zzCY = versionCode;
        this.zzasP = gameId;
        this.zzasQ = gameName;
        this.zzasR = activityTimestampMillis;
        this.zzasS = gameIconImageUri;
        this.zzasT = gameHiResIconImageUri;
        this.zzasU = gameFeaturedImageUri;
    }

    public MostRecentGameInfoEntity(MostRecentGameInfo info) {
        this.zzCY = 2;
        this.zzasP = info.zztu();
        this.zzasQ = info.zztv();
        this.zzasR = info.zztw();
        this.zzasS = info.zztx();
        this.zzasT = info.zzty();
        this.zzasU = info.zztz();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int zza(MostRecentGameInfo mostRecentGameInfo) {
        return zzt.hashCode(mostRecentGameInfo.zztu(), mostRecentGameInfo.zztv(), Long.valueOf(mostRecentGameInfo.zztw()), mostRecentGameInfo.zztx(), mostRecentGameInfo.zzty(), mostRecentGameInfo.zztz());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean zza(MostRecentGameInfo mostRecentGameInfo, Object obj) {
        if (obj instanceof MostRecentGameInfo) {
            if (mostRecentGameInfo != obj) {
                MostRecentGameInfo mostRecentGameInfo2 = (MostRecentGameInfo) obj;
                return zzt.equal(mostRecentGameInfo2.zztu(), mostRecentGameInfo.zztu()) && zzt.equal(mostRecentGameInfo2.zztv(), mostRecentGameInfo.zztv()) && zzt.equal(Long.valueOf(mostRecentGameInfo2.zztw()), Long.valueOf(mostRecentGameInfo.zztw())) && zzt.equal(mostRecentGameInfo2.zztx(), mostRecentGameInfo.zztx()) && zzt.equal(mostRecentGameInfo2.zzty(), mostRecentGameInfo.zzty()) && zzt.equal(mostRecentGameInfo2.zztz(), mostRecentGameInfo.zztz());
            }
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String zzb(MostRecentGameInfo mostRecentGameInfo) {
        return zzt.zzt(mostRecentGameInfo).zzg("GameId", mostRecentGameInfo.zztu()).zzg("GameName", mostRecentGameInfo.zztv()).zzg("ActivityTimestampMillis", Long.valueOf(mostRecentGameInfo.zztw())).zzg("GameIconUri", mostRecentGameInfo.zztx()).zzg("GameHiResUri", mostRecentGameInfo.zzty()).zzg("GameFeaturedUri", mostRecentGameInfo.zztz()).toString();
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object obj) {
        return zza(this, obj);
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return zza(this);
    }

    @Override // com.google.android.gms.common.data.Freezable
    public boolean isDataValid() {
        return true;
    }

    public String toString() {
        return zzb(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        MostRecentGameInfoEntityCreator.zza(this, out, flags);
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zztA */
    public MostRecentGameInfo freeze() {
        return this;
    }

    @Override // com.google.android.gms.games.internal.player.MostRecentGameInfo
    public String zztu() {
        return this.zzasP;
    }

    @Override // com.google.android.gms.games.internal.player.MostRecentGameInfo
    public String zztv() {
        return this.zzasQ;
    }

    @Override // com.google.android.gms.games.internal.player.MostRecentGameInfo
    public long zztw() {
        return this.zzasR;
    }

    @Override // com.google.android.gms.games.internal.player.MostRecentGameInfo
    public Uri zztx() {
        return this.zzasS;
    }

    @Override // com.google.android.gms.games.internal.player.MostRecentGameInfo
    public Uri zzty() {
        return this.zzasT;
    }

    @Override // com.google.android.gms.games.internal.player.MostRecentGameInfo
    public Uri zztz() {
        return this.zzasU;
    }
}
