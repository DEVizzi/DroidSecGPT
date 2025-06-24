package com.google.android.gms.games.internal.data;

import android.net.Uri;
import com.google.android.gms.games.Games;
/* loaded from: classes.dex */
public final class GamesDataChangeUris {
    private static final Uri zzasD = Uri.parse("content://com.google.android.gms.games/").buildUpon().appendPath("data_change").build();
    public static final Uri zzasE = zzasD.buildUpon().appendPath("invitations").build();
    public static final Uri zzasF = zzasD.buildUpon().appendEncodedPath(Games.EXTRA_PLAYER_IDS).build();
}
