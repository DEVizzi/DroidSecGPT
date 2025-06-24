package com.google.android.gms.games.internal.constants;
/* loaded from: classes.dex */
public final class LeaderboardCollection {
    private LeaderboardCollection() {
    }

    public static String zzfG(int i) {
        switch (i) {
            case 0:
                return "PUBLIC";
            case 1:
                return "SOCIAL";
            default:
                throw new IllegalArgumentException("Unknown leaderboard collection: " + i);
        }
    }
}
