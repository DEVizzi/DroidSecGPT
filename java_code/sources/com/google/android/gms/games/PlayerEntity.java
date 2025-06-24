package com.google.android.gms.games;

import android.database.CharArrayBuffer;
import android.net.Uri;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.zzb;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.games.internal.GamesDowngradeableSafeParcel;
import com.google.android.gms.games.internal.player.MostRecentGameInfo;
import com.google.android.gms.games.internal.player.MostRecentGameInfoEntity;
import com.google.android.gms.internal.zzlc;
/* loaded from: classes.dex */
public final class PlayerEntity extends GamesDowngradeableSafeParcel implements Player {
    public static final Parcelable.Creator<PlayerEntity> CREATOR = new PlayerEntityCreatorCompat();
    private final int zzCY;
    private final String zzTL;
    private final String zzadI;
    private final String zzadv;
    private final long zzanJ;
    private final int zzanK;
    private final long zzanL;
    private final MostRecentGameInfoEntity zzanM;
    private final PlayerLevelInfo zzanN;
    private final boolean zzanO;
    private final boolean zzanP;
    private final Uri zzanf;
    private final Uri zzang;
    private final String zzanq;
    private final String zzanr;

    /* loaded from: classes.dex */
    static final class PlayerEntityCreatorCompat extends PlayerEntityCreator {
        PlayerEntityCreatorCompat() {
        }

        @Override // com.google.android.gms.games.PlayerEntityCreator, android.os.Parcelable.Creator
        /* renamed from: zzds */
        public PlayerEntity createFromParcel(Parcel parcel) {
            if (PlayerEntity.zzd(PlayerEntity.zzrH()) || PlayerEntity.zzca(PlayerEntity.class.getCanonicalName())) {
                return super.createFromParcel(parcel);
            }
            String readString = parcel.readString();
            String readString2 = parcel.readString();
            String readString3 = parcel.readString();
            String readString4 = parcel.readString();
            return new PlayerEntity(12, readString, readString2, readString3 == null ? null : Uri.parse(readString3), readString4 == null ? null : Uri.parse(readString4), parcel.readLong(), -1, -1L, null, null, null, null, null, true, false);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public PlayerEntity(int versionCode, String playerId, String displayName, Uri iconImageUri, Uri hiResImageUri, long retrievedTimestamp, int isInCircles, long lastPlayedWithTimestamp, String iconImageUrl, String hiResImageUrl, String title, MostRecentGameInfoEntity mostRecentGameInfo, PlayerLevelInfo playerLevelInfo, boolean isProfileVisible, boolean hasDebugAccess) {
        this.zzCY = versionCode;
        this.zzTL = playerId;
        this.zzadI = displayName;
        this.zzanf = iconImageUri;
        this.zzanq = iconImageUrl;
        this.zzang = hiResImageUri;
        this.zzanr = hiResImageUrl;
        this.zzanJ = retrievedTimestamp;
        this.zzanK = isInCircles;
        this.zzanL = lastPlayedWithTimestamp;
        this.zzadv = title;
        this.zzanO = isProfileVisible;
        this.zzanM = mostRecentGameInfo;
        this.zzanN = playerLevelInfo;
        this.zzanP = hasDebugAccess;
    }

    public PlayerEntity(Player player) {
        this(player, true);
    }

    public PlayerEntity(Player player, boolean isPlusEnabled) {
        this.zzCY = 12;
        this.zzTL = isPlusEnabled ? player.getPlayerId() : null;
        this.zzadI = player.getDisplayName();
        this.zzanf = player.getIconImageUri();
        this.zzanq = player.getIconImageUrl();
        this.zzang = player.getHiResImageUri();
        this.zzanr = player.getHiResImageUrl();
        this.zzanJ = player.getRetrievedTimestamp();
        this.zzanK = player.zzrK();
        this.zzanL = player.getLastPlayedWithTimestamp();
        this.zzadv = player.getTitle();
        this.zzanO = player.isProfileVisible();
        MostRecentGameInfo zzrL = player.zzrL();
        this.zzanM = zzrL != null ? new MostRecentGameInfoEntity(zzrL) : null;
        this.zzanN = player.getLevelInfo();
        this.zzanP = player.zzrJ();
        if (isPlusEnabled) {
            zzb.zzq(this.zzTL);
        }
        zzb.zzq(this.zzadI);
        zzb.zzU(this.zzanJ > 0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean zza(Player player, Object obj) {
        if (obj instanceof Player) {
            if (player != obj) {
                Player player2 = (Player) obj;
                return zzt.equal(player2.getPlayerId(), player.getPlayerId()) && zzt.equal(player2.getDisplayName(), player.getDisplayName()) && zzt.equal(Boolean.valueOf(player2.zzrJ()), Boolean.valueOf(player.zzrJ())) && zzt.equal(player2.getIconImageUri(), player.getIconImageUri()) && zzt.equal(player2.getHiResImageUri(), player.getHiResImageUri()) && zzt.equal(Long.valueOf(player2.getRetrievedTimestamp()), Long.valueOf(player.getRetrievedTimestamp())) && zzt.equal(player2.getTitle(), player.getTitle()) && zzt.equal(player2.getLevelInfo(), player.getLevelInfo());
            }
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int zzb(Player player) {
        return zzt.hashCode(player.getPlayerId(), player.getDisplayName(), Boolean.valueOf(player.zzrJ()), player.getIconImageUri(), player.getHiResImageUri(), Long.valueOf(player.getRetrievedTimestamp()), player.getTitle(), player.getLevelInfo());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String zzc(Player player) {
        return zzt.zzt(player).zzg("PlayerId", player.getPlayerId()).zzg("DisplayName", player.getDisplayName()).zzg("HasDebugAccess", Boolean.valueOf(player.zzrJ())).zzg("IconImageUri", player.getIconImageUri()).zzg("IconImageUrl", player.getIconImageUrl()).zzg("HiResImageUri", player.getHiResImageUri()).zzg("HiResImageUrl", player.getHiResImageUrl()).zzg("RetrievedTimestamp", Long.valueOf(player.getRetrievedTimestamp())).zzg("Title", player.getTitle()).zzg("LevelInfo", player.getLevelInfo()).toString();
    }

    static /* synthetic */ Integer zzrH() {
        return zznE();
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
    public Player freeze() {
        return this;
    }

    @Override // com.google.android.gms.games.Player
    public String getDisplayName() {
        return this.zzadI;
    }

    @Override // com.google.android.gms.games.Player
    public void getDisplayName(CharArrayBuffer dataOut) {
        zzlc.zzb(this.zzadI, dataOut);
    }

    @Override // com.google.android.gms.games.Player
    public Uri getHiResImageUri() {
        return this.zzang;
    }

    @Override // com.google.android.gms.games.Player
    public String getHiResImageUrl() {
        return this.zzanr;
    }

    @Override // com.google.android.gms.games.Player
    public Uri getIconImageUri() {
        return this.zzanf;
    }

    @Override // com.google.android.gms.games.Player
    public String getIconImageUrl() {
        return this.zzanq;
    }

    @Override // com.google.android.gms.games.Player
    public long getLastPlayedWithTimestamp() {
        return this.zzanL;
    }

    @Override // com.google.android.gms.games.Player
    public PlayerLevelInfo getLevelInfo() {
        return this.zzanN;
    }

    @Override // com.google.android.gms.games.Player
    public String getPlayerId() {
        return this.zzTL;
    }

    @Override // com.google.android.gms.games.Player
    public long getRetrievedTimestamp() {
        return this.zzanJ;
    }

    @Override // com.google.android.gms.games.Player
    public String getTitle() {
        return this.zzadv;
    }

    @Override // com.google.android.gms.games.Player
    public void getTitle(CharArrayBuffer dataOut) {
        zzlc.zzb(this.zzadv, dataOut);
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // com.google.android.gms.games.Player
    public boolean hasHiResImage() {
        return getHiResImageUri() != null;
    }

    @Override // com.google.android.gms.games.Player
    public boolean hasIconImage() {
        return getIconImageUri() != null;
    }

    public int hashCode() {
        return zzb(this);
    }

    @Override // com.google.android.gms.common.data.Freezable
    public boolean isDataValid() {
        return true;
    }

    @Override // com.google.android.gms.games.Player
    public boolean isProfileVisible() {
        return this.zzanO;
    }

    public String toString() {
        return zzc(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        if (!zznF()) {
            PlayerEntityCreator.zza(this, dest, flags);
            return;
        }
        dest.writeString(this.zzTL);
        dest.writeString(this.zzadI);
        dest.writeString(this.zzanf == null ? null : this.zzanf.toString());
        dest.writeString(this.zzang != null ? this.zzang.toString() : null);
        dest.writeLong(this.zzanJ);
    }

    @Override // com.google.android.gms.games.Player
    public boolean zzrJ() {
        return this.zzanP;
    }

    @Override // com.google.android.gms.games.Player
    public int zzrK() {
        return this.zzanK;
    }

    @Override // com.google.android.gms.games.Player
    public MostRecentGameInfo zzrL() {
        return this.zzanM;
    }
}
