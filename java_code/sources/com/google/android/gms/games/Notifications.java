package com.google.android.gms.games;

import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Result;
/* loaded from: classes.dex */
public interface Notifications {
    public static final int NOTIFICATION_TYPES_ALL = 31;
    public static final int NOTIFICATION_TYPES_MULTIPLAYER = 3;
    public static final int NOTIFICATION_TYPE_INVITATION = 1;
    public static final int NOTIFICATION_TYPE_LEVEL_UP = 16;
    public static final int NOTIFICATION_TYPE_MATCH_UPDATE = 2;
    public static final int NOTIFICATION_TYPE_QUEST = 8;
    public static final int NOTIFICATION_TYPE_REQUEST = 4;

    /* loaded from: classes.dex */
    public interface ContactSettingLoadResult extends Result {
    }

    /* loaded from: classes.dex */
    public interface GameMuteStatusChangeResult extends Result {
    }

    /* loaded from: classes.dex */
    public interface GameMuteStatusLoadResult extends Result {
    }

    /* loaded from: classes.dex */
    public interface InboxCountResult extends Result {
    }

    void clear(GoogleApiClient googleApiClient, int i);

    void clearAll(GoogleApiClient googleApiClient);
}
