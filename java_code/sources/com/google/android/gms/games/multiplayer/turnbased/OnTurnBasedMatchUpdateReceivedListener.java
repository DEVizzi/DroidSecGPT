package com.google.android.gms.games.multiplayer.turnbased;
/* loaded from: classes.dex */
public interface OnTurnBasedMatchUpdateReceivedListener {
    void onTurnBasedMatchReceived(TurnBasedMatch turnBasedMatch);

    void onTurnBasedMatchRemoved(String str);
}
