package com.google.android.gms.games;

import android.database.CharArrayBuffer;
import android.net.Uri;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.games.internal.GamesDowngradeableSafeParcel;
import com.google.android.gms.internal.zzlc;
/* loaded from: classes.dex */
public final class GameEntity extends GamesDowngradeableSafeParcel implements Game {
    public static final Parcelable.Creator<GameEntity> CREATOR = new GameEntityCreatorCompat();
    private final boolean zzAg;
    private final int zzCY;
    private final String zzQv;
    private final String zzadI;
    private final String zzakM;
    private final String zzanc;
    private final String zzand;
    private final String zzane;
    private final Uri zzanf;
    private final Uri zzang;
    private final Uri zzanh;
    private final boolean zzani;
    private final boolean zzanj;
    private final String zzank;
    private final int zzanl;
    private final int zzanm;
    private final int zzann;
    private final boolean zzano;
    private final boolean zzanp;
    private final String zzanq;
    private final String zzanr;
    private final String zzans;
    private final boolean zzant;
    private final boolean zzanu;
    private final String zzanv;
    private final boolean zzanw;

    /* loaded from: classes.dex */
    static final class GameEntityCreatorCompat extends GameEntityCreator {
        GameEntityCreatorCompat() {
        }

        @Override // com.google.android.gms.games.GameEntityCreator, android.os.Parcelable.Creator
        /* renamed from: zzdr */
        public GameEntity createFromParcel(Parcel parcel) {
            if (GameEntity.zzd(GameEntity.zzrH()) || GameEntity.zzca(GameEntity.class.getCanonicalName())) {
                return super.createFromParcel(parcel);
            }
            String readString = parcel.readString();
            String readString2 = parcel.readString();
            String readString3 = parcel.readString();
            String readString4 = parcel.readString();
            String readString5 = parcel.readString();
            String readString6 = parcel.readString();
            String readString7 = parcel.readString();
            Uri parse = readString7 == null ? null : Uri.parse(readString7);
            String readString8 = parcel.readString();
            Uri parse2 = readString8 == null ? null : Uri.parse(readString8);
            String readString9 = parcel.readString();
            return new GameEntity(7, readString, readString2, readString3, readString4, readString5, readString6, parse, parse2, readString9 == null ? null : Uri.parse(readString9), parcel.readInt() > 0, parcel.readInt() > 0, parcel.readString(), parcel.readInt(), parcel.readInt(), parcel.readInt(), false, false, null, null, null, false, false, false, null, false);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public GameEntity(int versionCode, String applicationId, String displayName, String primaryCategory, String secondaryCategory, String description, String developerName, Uri iconImageUri, Uri hiResImageUri, Uri featuredImageUri, boolean playEnabledGame, boolean instanceInstalled, String instancePackageName, int gameplayAclStatus, int achievementTotalCount, int leaderboardCount, boolean realTimeEnabled, boolean turnBasedEnabled, String iconImageUrl, String hiResImageUrl, String featuredImageUrl, boolean muted, boolean identitySharingConfirmed, boolean snapshotsEnabled, String themeColor, boolean hasGamepadSupport) {
        this.zzCY = versionCode;
        this.zzQv = applicationId;
        this.zzadI = displayName;
        this.zzanc = primaryCategory;
        this.zzand = secondaryCategory;
        this.zzakM = description;
        this.zzane = developerName;
        this.zzanf = iconImageUri;
        this.zzanq = iconImageUrl;
        this.zzang = hiResImageUri;
        this.zzanr = hiResImageUrl;
        this.zzanh = featuredImageUri;
        this.zzans = featuredImageUrl;
        this.zzani = playEnabledGame;
        this.zzanj = instanceInstalled;
        this.zzank = instancePackageName;
        this.zzanl = gameplayAclStatus;
        this.zzanm = achievementTotalCount;
        this.zzann = leaderboardCount;
        this.zzano = realTimeEnabled;
        this.zzanp = turnBasedEnabled;
        this.zzAg = muted;
        this.zzant = identitySharingConfirmed;
        this.zzanu = snapshotsEnabled;
        this.zzanv = themeColor;
        this.zzanw = hasGamepadSupport;
    }

    public GameEntity(Game game) {
        this.zzCY = 7;
        this.zzQv = game.getApplicationId();
        this.zzanc = game.getPrimaryCategory();
        this.zzand = game.getSecondaryCategory();
        this.zzakM = game.getDescription();
        this.zzane = game.getDeveloperName();
        this.zzadI = game.getDisplayName();
        this.zzanf = game.getIconImageUri();
        this.zzanq = game.getIconImageUrl();
        this.zzang = game.getHiResImageUri();
        this.zzanr = game.getHiResImageUrl();
        this.zzanh = game.getFeaturedImageUri();
        this.zzans = game.getFeaturedImageUrl();
        this.zzani = game.zzrC();
        this.zzanj = game.zzrE();
        this.zzank = game.zzrF();
        this.zzanl = game.zzrG();
        this.zzanm = game.getAchievementTotalCount();
        this.zzann = game.getLeaderboardCount();
        this.zzano = game.isRealTimeMultiplayerEnabled();
        this.zzanp = game.isTurnBasedMultiplayerEnabled();
        this.zzAg = game.isMuted();
        this.zzant = game.zzrD();
        this.zzanu = game.areSnapshotsEnabled();
        this.zzanv = game.getThemeColor();
        this.zzanw = game.hasGamepadSupport();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int zza(Game game) {
        return zzt.hashCode(game.getApplicationId(), game.getDisplayName(), game.getPrimaryCategory(), game.getSecondaryCategory(), game.getDescription(), game.getDeveloperName(), game.getIconImageUri(), game.getHiResImageUri(), game.getFeaturedImageUri(), Boolean.valueOf(game.zzrC()), Boolean.valueOf(game.zzrE()), game.zzrF(), Integer.valueOf(game.zzrG()), Integer.valueOf(game.getAchievementTotalCount()), Integer.valueOf(game.getLeaderboardCount()), Boolean.valueOf(game.isRealTimeMultiplayerEnabled()), Boolean.valueOf(game.isTurnBasedMultiplayerEnabled()), Boolean.valueOf(game.isMuted()), Boolean.valueOf(game.zzrD()), Boolean.valueOf(game.areSnapshotsEnabled()), game.getThemeColor(), Boolean.valueOf(game.hasGamepadSupport()));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean zza(Game game, Object obj) {
        if (obj instanceof Game) {
            if (game != obj) {
                Game game2 = (Game) obj;
                if (zzt.equal(game2.getApplicationId(), game.getApplicationId()) && zzt.equal(game2.getDisplayName(), game.getDisplayName()) && zzt.equal(game2.getPrimaryCategory(), game.getPrimaryCategory()) && zzt.equal(game2.getSecondaryCategory(), game.getSecondaryCategory()) && zzt.equal(game2.getDescription(), game.getDescription()) && zzt.equal(game2.getDeveloperName(), game.getDeveloperName()) && zzt.equal(game2.getIconImageUri(), game.getIconImageUri()) && zzt.equal(game2.getHiResImageUri(), game.getHiResImageUri()) && zzt.equal(game2.getFeaturedImageUri(), game.getFeaturedImageUri()) && zzt.equal(Boolean.valueOf(game2.zzrC()), Boolean.valueOf(game.zzrC())) && zzt.equal(Boolean.valueOf(game2.zzrE()), Boolean.valueOf(game.zzrE())) && zzt.equal(game2.zzrF(), game.zzrF()) && zzt.equal(Integer.valueOf(game2.zzrG()), Integer.valueOf(game.zzrG())) && zzt.equal(Integer.valueOf(game2.getAchievementTotalCount()), Integer.valueOf(game.getAchievementTotalCount())) && zzt.equal(Integer.valueOf(game2.getLeaderboardCount()), Integer.valueOf(game.getLeaderboardCount())) && zzt.equal(Boolean.valueOf(game2.isRealTimeMultiplayerEnabled()), Boolean.valueOf(game.isRealTimeMultiplayerEnabled()))) {
                    if (zzt.equal(Boolean.valueOf(game2.isTurnBasedMultiplayerEnabled()), Boolean.valueOf(game.isTurnBasedMultiplayerEnabled() && zzt.equal(Boolean.valueOf(game2.isMuted()), Boolean.valueOf(game.isMuted())) && zzt.equal(Boolean.valueOf(game2.zzrD()), Boolean.valueOf(game.zzrD())))) && zzt.equal(Boolean.valueOf(game2.areSnapshotsEnabled()), Boolean.valueOf(game.areSnapshotsEnabled())) && zzt.equal(game2.getThemeColor(), game.getThemeColor()) && zzt.equal(Boolean.valueOf(game2.hasGamepadSupport()), Boolean.valueOf(game.hasGamepadSupport()))) {
                        return true;
                    }
                }
                return false;
            }
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String zzb(Game game) {
        return zzt.zzt(game).zzg("ApplicationId", game.getApplicationId()).zzg("DisplayName", game.getDisplayName()).zzg("PrimaryCategory", game.getPrimaryCategory()).zzg("SecondaryCategory", game.getSecondaryCategory()).zzg("Description", game.getDescription()).zzg("DeveloperName", game.getDeveloperName()).zzg("IconImageUri", game.getIconImageUri()).zzg("IconImageUrl", game.getIconImageUrl()).zzg("HiResImageUri", game.getHiResImageUri()).zzg("HiResImageUrl", game.getHiResImageUrl()).zzg("FeaturedImageUri", game.getFeaturedImageUri()).zzg("FeaturedImageUrl", game.getFeaturedImageUrl()).zzg("PlayEnabledGame", Boolean.valueOf(game.zzrC())).zzg("InstanceInstalled", Boolean.valueOf(game.zzrE())).zzg("InstancePackageName", game.zzrF()).zzg("AchievementTotalCount", Integer.valueOf(game.getAchievementTotalCount())).zzg("LeaderboardCount", Integer.valueOf(game.getLeaderboardCount())).zzg("RealTimeMultiplayerEnabled", Boolean.valueOf(game.isRealTimeMultiplayerEnabled())).zzg("TurnBasedMultiplayerEnabled", Boolean.valueOf(game.isTurnBasedMultiplayerEnabled())).zzg("AreSnapshotsEnabled", Boolean.valueOf(game.areSnapshotsEnabled())).zzg("ThemeColor", game.getThemeColor()).zzg("HasGamepadSupport", Boolean.valueOf(game.hasGamepadSupport())).toString();
    }

    static /* synthetic */ Integer zzrH() {
        return zznE();
    }

    @Override // com.google.android.gms.games.Game
    public boolean areSnapshotsEnabled() {
        return this.zzanu;
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
    public Game freeze() {
        return this;
    }

    @Override // com.google.android.gms.games.Game
    public int getAchievementTotalCount() {
        return this.zzanm;
    }

    @Override // com.google.android.gms.games.Game
    public String getApplicationId() {
        return this.zzQv;
    }

    @Override // com.google.android.gms.games.Game
    public String getDescription() {
        return this.zzakM;
    }

    @Override // com.google.android.gms.games.Game
    public void getDescription(CharArrayBuffer dataOut) {
        zzlc.zzb(this.zzakM, dataOut);
    }

    @Override // com.google.android.gms.games.Game
    public String getDeveloperName() {
        return this.zzane;
    }

    @Override // com.google.android.gms.games.Game
    public void getDeveloperName(CharArrayBuffer dataOut) {
        zzlc.zzb(this.zzane, dataOut);
    }

    @Override // com.google.android.gms.games.Game
    public String getDisplayName() {
        return this.zzadI;
    }

    @Override // com.google.android.gms.games.Game
    public void getDisplayName(CharArrayBuffer dataOut) {
        zzlc.zzb(this.zzadI, dataOut);
    }

    @Override // com.google.android.gms.games.Game
    public Uri getFeaturedImageUri() {
        return this.zzanh;
    }

    @Override // com.google.android.gms.games.Game
    public String getFeaturedImageUrl() {
        return this.zzans;
    }

    @Override // com.google.android.gms.games.Game
    public Uri getHiResImageUri() {
        return this.zzang;
    }

    @Override // com.google.android.gms.games.Game
    public String getHiResImageUrl() {
        return this.zzanr;
    }

    @Override // com.google.android.gms.games.Game
    public Uri getIconImageUri() {
        return this.zzanf;
    }

    @Override // com.google.android.gms.games.Game
    public String getIconImageUrl() {
        return this.zzanq;
    }

    @Override // com.google.android.gms.games.Game
    public int getLeaderboardCount() {
        return this.zzann;
    }

    @Override // com.google.android.gms.games.Game
    public String getPrimaryCategory() {
        return this.zzanc;
    }

    @Override // com.google.android.gms.games.Game
    public String getSecondaryCategory() {
        return this.zzand;
    }

    @Override // com.google.android.gms.games.Game
    public String getThemeColor() {
        return this.zzanv;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // com.google.android.gms.games.Game
    public boolean hasGamepadSupport() {
        return this.zzanw;
    }

    public int hashCode() {
        return zza(this);
    }

    @Override // com.google.android.gms.common.data.Freezable
    public boolean isDataValid() {
        return true;
    }

    @Override // com.google.android.gms.games.Game
    public boolean isMuted() {
        return this.zzAg;
    }

    @Override // com.google.android.gms.games.Game
    public boolean isRealTimeMultiplayerEnabled() {
        return this.zzano;
    }

    @Override // com.google.android.gms.games.Game
    public boolean isTurnBasedMultiplayerEnabled() {
        return this.zzanp;
    }

    public String toString() {
        return zzb(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        if (!zznF()) {
            GameEntityCreator.zza(this, dest, flags);
            return;
        }
        dest.writeString(this.zzQv);
        dest.writeString(this.zzadI);
        dest.writeString(this.zzanc);
        dest.writeString(this.zzand);
        dest.writeString(this.zzakM);
        dest.writeString(this.zzane);
        dest.writeString(this.zzanf == null ? null : this.zzanf.toString());
        dest.writeString(this.zzang == null ? null : this.zzang.toString());
        dest.writeString(this.zzanh != null ? this.zzanh.toString() : null);
        dest.writeInt(this.zzani ? 1 : 0);
        dest.writeInt(this.zzanj ? 1 : 0);
        dest.writeString(this.zzank);
        dest.writeInt(this.zzanl);
        dest.writeInt(this.zzanm);
        dest.writeInt(this.zzann);
    }

    @Override // com.google.android.gms.games.Game
    public boolean zzrC() {
        return this.zzani;
    }

    @Override // com.google.android.gms.games.Game
    public boolean zzrD() {
        return this.zzant;
    }

    @Override // com.google.android.gms.games.Game
    public boolean zzrE() {
        return this.zzanj;
    }

    @Override // com.google.android.gms.games.Game
    public String zzrF() {
        return this.zzank;
    }

    @Override // com.google.android.gms.games.Game
    public int zzrG() {
        return this.zzanl;
    }
}
