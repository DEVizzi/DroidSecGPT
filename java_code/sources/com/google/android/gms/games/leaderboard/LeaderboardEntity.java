package com.google.android.gms.games.leaderboard;

import android.database.CharArrayBuffer;
import android.net.Uri;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.games.Game;
import com.google.android.gms.games.GameEntity;
import com.google.android.gms.internal.zzlc;
import java.util.ArrayList;
/* loaded from: classes.dex */
public final class LeaderboardEntity implements Leaderboard {
    private final String zzadI;
    private final Uri zzanf;
    private final String zzanq;
    private final ArrayList<LeaderboardVariantEntity> zzatA;
    private final Game zzatB;
    private final String zzaty;
    private final int zzatz;

    public LeaderboardEntity(Leaderboard leaderboard) {
        this.zzaty = leaderboard.getLeaderboardId();
        this.zzadI = leaderboard.getDisplayName();
        this.zzanf = leaderboard.getIconImageUri();
        this.zzanq = leaderboard.getIconImageUrl();
        this.zzatz = leaderboard.getScoreOrder();
        Game game = leaderboard.getGame();
        this.zzatB = game == null ? null : new GameEntity(game);
        ArrayList<LeaderboardVariant> variants = leaderboard.getVariants();
        int size = variants.size();
        this.zzatA = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            this.zzatA.add((LeaderboardVariantEntity) variants.get(i).freeze());
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int zza(Leaderboard leaderboard) {
        return zzt.hashCode(leaderboard.getLeaderboardId(), leaderboard.getDisplayName(), leaderboard.getIconImageUri(), Integer.valueOf(leaderboard.getScoreOrder()), leaderboard.getVariants());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean zza(Leaderboard leaderboard, Object obj) {
        if (obj instanceof Leaderboard) {
            if (leaderboard != obj) {
                Leaderboard leaderboard2 = (Leaderboard) obj;
                return zzt.equal(leaderboard2.getLeaderboardId(), leaderboard.getLeaderboardId()) && zzt.equal(leaderboard2.getDisplayName(), leaderboard.getDisplayName()) && zzt.equal(leaderboard2.getIconImageUri(), leaderboard.getIconImageUri()) && zzt.equal(Integer.valueOf(leaderboard2.getScoreOrder()), Integer.valueOf(leaderboard.getScoreOrder())) && zzt.equal(leaderboard2.getVariants(), leaderboard.getVariants());
            }
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String zzb(Leaderboard leaderboard) {
        return zzt.zzt(leaderboard).zzg("LeaderboardId", leaderboard.getLeaderboardId()).zzg("DisplayName", leaderboard.getDisplayName()).zzg("IconImageUri", leaderboard.getIconImageUri()).zzg("IconImageUrl", leaderboard.getIconImageUrl()).zzg("ScoreOrder", Integer.valueOf(leaderboard.getScoreOrder())).zzg("Variants", leaderboard.getVariants()).toString();
    }

    public boolean equals(Object obj) {
        return zza(this, obj);
    }

    @Override // com.google.android.gms.games.leaderboard.Leaderboard
    public String getDisplayName() {
        return this.zzadI;
    }

    @Override // com.google.android.gms.games.leaderboard.Leaderboard
    public void getDisplayName(CharArrayBuffer dataOut) {
        zzlc.zzb(this.zzadI, dataOut);
    }

    @Override // com.google.android.gms.games.leaderboard.Leaderboard
    public Game getGame() {
        return this.zzatB;
    }

    @Override // com.google.android.gms.games.leaderboard.Leaderboard
    public Uri getIconImageUri() {
        return this.zzanf;
    }

    @Override // com.google.android.gms.games.leaderboard.Leaderboard
    public String getIconImageUrl() {
        return this.zzanq;
    }

    @Override // com.google.android.gms.games.leaderboard.Leaderboard
    public String getLeaderboardId() {
        return this.zzaty;
    }

    @Override // com.google.android.gms.games.leaderboard.Leaderboard
    public int getScoreOrder() {
        return this.zzatz;
    }

    @Override // com.google.android.gms.games.leaderboard.Leaderboard
    public ArrayList<LeaderboardVariant> getVariants() {
        return new ArrayList<>(this.zzatA);
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

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zztE */
    public Leaderboard freeze() {
        return this;
    }
}
