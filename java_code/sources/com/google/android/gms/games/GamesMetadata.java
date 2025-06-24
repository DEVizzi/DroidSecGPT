package com.google.android.gms.games;

import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Releasable;
import com.google.android.gms.common.api.Result;
/* loaded from: classes.dex */
public interface GamesMetadata {

    /* loaded from: classes.dex */
    public interface LoadGameInstancesResult extends Releasable, Result {
    }

    /* loaded from: classes.dex */
    public interface LoadGameSearchSuggestionsResult extends Releasable, Result {
    }

    /* loaded from: classes.dex */
    public interface LoadGamesResult extends Releasable, Result {
        GameBuffer getGames();
    }

    Game getCurrentGame(GoogleApiClient googleApiClient);

    PendingResult<LoadGamesResult> loadGame(GoogleApiClient googleApiClient);
}
