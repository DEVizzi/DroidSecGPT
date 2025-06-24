package com.google.android.gms.games.leaderboard;

import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.data.zzf;
/* loaded from: classes.dex */
public final class LeaderboardBuffer extends zzf<Leaderboard> {
    public LeaderboardBuffer(DataHolder dataHolder) {
        super(dataHolder);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.data.zzf
    /* renamed from: zzn */
    public Leaderboard zzj(int i, int i2) {
        return new LeaderboardRef(this.zzWu, i, i2);
    }

    @Override // com.google.android.gms.common.data.zzf
    protected String zzni() {
        return "external_leaderboard_id";
    }
}
