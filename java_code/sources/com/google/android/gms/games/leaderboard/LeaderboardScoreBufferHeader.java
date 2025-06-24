package com.google.android.gms.games.leaderboard;

import android.os.Bundle;
/* loaded from: classes.dex */
public final class LeaderboardScoreBufferHeader {
    private final Bundle zzNW;

    /* loaded from: classes.dex */
    public static final class Builder {
        private Builder() {
        }
    }

    public LeaderboardScoreBufferHeader(Bundle bundle) {
        this.zzNW = bundle == null ? new Bundle() : bundle;
    }

    public Bundle asBundle() {
        return this.zzNW;
    }
}
