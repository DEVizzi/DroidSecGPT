package android.support.v7.media;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.os.Bundle;
import android.support.v7.media.MediaRouter;
import android.util.Log;
/* loaded from: classes.dex */
public class RemotePlaybackClient {
    private final Context mContext;
    private final PendingIntent mItemStatusPendingIntent;
    private final MediaRouter.RouteInfo mRoute;
    private boolean mRouteSupportsQueuing;
    private boolean mRouteSupportsRemotePlayback;
    private boolean mRouteSupportsSessionManagement;
    private String mSessionId;
    private final PendingIntent mSessionStatusPendingIntent;
    private StatusCallback mStatusCallback;
    private final StatusReceiver mStatusReceiver;
    private static final String TAG = "RemotePlaybackClient";
    private static final boolean DEBUG = Log.isLoggable(TAG, 3);

    public RemotePlaybackClient(Context context, MediaRouter.RouteInfo route) {
        if (context == null) {
            throw new IllegalArgumentException("context must not be null");
        }
        if (route == null) {
            throw new IllegalArgumentException("route must not be null");
        }
        this.mContext = context;
        this.mRoute = route;
        IntentFilter statusFilter = new IntentFilter();
        statusFilter.addAction(StatusReceiver.ACTION_ITEM_STATUS_CHANGED);
        statusFilter.addAction(StatusReceiver.ACTION_SESSION_STATUS_CHANGED);
        this.mStatusReceiver = new StatusReceiver();
        context.registerReceiver(this.mStatusReceiver, statusFilter);
        Intent itemStatusIntent = new Intent(StatusReceiver.ACTION_ITEM_STATUS_CHANGED);
        itemStatusIntent.setPackage(context.getPackageName());
        this.mItemStatusPendingIntent = PendingIntent.getBroadcast(context, 0, itemStatusIntent, 0);
        Intent sessionStatusIntent = new Intent(StatusReceiver.ACTION_SESSION_STATUS_CHANGED);
        sessionStatusIntent.setPackage(context.getPackageName());
        this.mSessionStatusPendingIntent = PendingIntent.getBroadcast(context, 0, sessionStatusIntent, 0);
        detectFeatures();
    }

    public void release() {
        this.mContext.unregisterReceiver(this.mStatusReceiver);
    }

    public boolean isRemotePlaybackSupported() {
        return this.mRouteSupportsRemotePlayback;
    }

    public boolean isQueuingSupported() {
        return this.mRouteSupportsQueuing;
    }

    public boolean isSessionManagementSupported() {
        return this.mRouteSupportsSessionManagement;
    }

    public String getSessionId() {
        return this.mSessionId;
    }

    public void setSessionId(String sessionId) {
        if (this.mSessionId != sessionId) {
            if (this.mSessionId == null || !this.mSessionId.equals(sessionId)) {
                if (DEBUG) {
                    Log.d(TAG, "Session id is now: " + sessionId);
                }
                this.mSessionId = sessionId;
                if (this.mStatusCallback != null) {
                    this.mStatusCallback.onSessionChanged(sessionId);
                }
            }
        }
    }

    public boolean hasSession() {
        return this.mSessionId != null;
    }

    public void setStatusCallback(StatusCallback callback) {
        this.mStatusCallback = callback;
    }

    public void play(Uri contentUri, String mimeType, Bundle metadata, long positionMillis, Bundle extras, ItemActionCallback callback) {
        playOrEnqueue(contentUri, mimeType, metadata, positionMillis, extras, callback, MediaControlIntent.ACTION_PLAY);
    }

    public void enqueue(Uri contentUri, String mimeType, Bundle metadata, long positionMillis, Bundle extras, ItemActionCallback callback) {
        playOrEnqueue(contentUri, mimeType, metadata, positionMillis, extras, callback, MediaControlIntent.ACTION_ENQUEUE);
    }

    private void playOrEnqueue(Uri contentUri, String mimeType, Bundle metadata, long positionMillis, Bundle extras, ItemActionCallback callback, String action) {
        if (contentUri == null) {
            throw new IllegalArgumentException("contentUri must not be null");
        }
        throwIfRemotePlaybackNotSupported();
        if (action.equals(MediaControlIntent.ACTION_ENQUEUE)) {
            throwIfQueuingNotSupported();
        }
        Intent intent = new Intent(action);
        intent.setDataAndType(contentUri, mimeType);
        intent.putExtra(MediaControlIntent.EXTRA_ITEM_STATUS_UPDATE_RECEIVER, this.mItemStatusPendingIntent);
        if (metadata != null) {
            intent.putExtra(MediaControlIntent.EXTRA_ITEM_METADATA, metadata);
        }
        if (positionMillis != 0) {
            intent.putExtra(MediaControlIntent.EXTRA_ITEM_CONTENT_POSITION, positionMillis);
        }
        performItemAction(intent, this.mSessionId, null, extras, callback);
    }

    public void seek(String itemId, long positionMillis, Bundle extras, ItemActionCallback callback) {
        if (itemId == null) {
            throw new IllegalArgumentException("itemId must not be null");
        }
        throwIfNoCurrentSession();
        Intent intent = new Intent(MediaControlIntent.ACTION_SEEK);
        intent.putExtra(MediaControlIntent.EXTRA_ITEM_CONTENT_POSITION, positionMillis);
        performItemAction(intent, this.mSessionId, itemId, extras, callback);
    }

    public void getStatus(String itemId, Bundle extras, ItemActionCallback callback) {
        if (itemId == null) {
            throw new IllegalArgumentException("itemId must not be null");
        }
        throwIfNoCurrentSession();
        Intent intent = new Intent(MediaControlIntent.ACTION_GET_STATUS);
        performItemAction(intent, this.mSessionId, itemId, extras, callback);
    }

    public void remove(String itemId, Bundle extras, ItemActionCallback callback) {
        if (itemId == null) {
            throw new IllegalArgumentException("itemId must not be null");
        }
        throwIfQueuingNotSupported();
        throwIfNoCurrentSession();
        Intent intent = new Intent(MediaControlIntent.ACTION_REMOVE);
        performItemAction(intent, this.mSessionId, itemId, extras, callback);
    }

    public void pause(Bundle extras, SessionActionCallback callback) {
        throwIfNoCurrentSession();
        Intent intent = new Intent(MediaControlIntent.ACTION_PAUSE);
        performSessionAction(intent, this.mSessionId, extras, callback);
    }

    public void resume(Bundle extras, SessionActionCallback callback) {
        throwIfNoCurrentSession();
        Intent intent = new Intent(MediaControlIntent.ACTION_RESUME);
        performSessionAction(intent, this.mSessionId, extras, callback);
    }

    public void stop(Bundle extras, SessionActionCallback callback) {
        throwIfNoCurrentSession();
        Intent intent = new Intent(MediaControlIntent.ACTION_STOP);
        performSessionAction(intent, this.mSessionId, extras, callback);
    }

    public void startSession(Bundle extras, SessionActionCallback callback) {
        throwIfSessionManagementNotSupported();
        Intent intent = new Intent(MediaControlIntent.ACTION_START_SESSION);
        intent.putExtra(MediaControlIntent.EXTRA_SESSION_STATUS_UPDATE_RECEIVER, this.mSessionStatusPendingIntent);
        performSessionAction(intent, null, extras, callback);
    }

    public void getSessionStatus(Bundle extras, SessionActionCallback callback) {
        throwIfSessionManagementNotSupported();
        throwIfNoCurrentSession();
        Intent intent = new Intent(MediaControlIntent.ACTION_GET_SESSION_STATUS);
        performSessionAction(intent, this.mSessionId, extras, callback);
    }

    public void endSession(Bundle extras, SessionActionCallback callback) {
        throwIfSessionManagementNotSupported();
        throwIfNoCurrentSession();
        Intent intent = new Intent(MediaControlIntent.ACTION_END_SESSION);
        performSessionAction(intent, this.mSessionId, extras, callback);
    }

    private void performItemAction(final Intent intent, final String sessionId, final String itemId, Bundle extras, final ItemActionCallback callback) {
        intent.addCategory(MediaControlIntent.CATEGORY_REMOTE_PLAYBACK);
        if (sessionId != null) {
            intent.putExtra(MediaControlIntent.EXTRA_SESSION_ID, sessionId);
        }
        if (itemId != null) {
            intent.putExtra(MediaControlIntent.EXTRA_ITEM_ID, itemId);
        }
        if (extras != null) {
            intent.putExtras(extras);
        }
        logRequest(intent);
        this.mRoute.sendControlRequest(intent, new MediaRouter.ControlRequestCallback() { // from class: android.support.v7.media.RemotePlaybackClient.1
            @Override // android.support.v7.media.MediaRouter.ControlRequestCallback
            public void onResult(Bundle data) {
                if (data != null) {
                    String sessionIdResult = RemotePlaybackClient.inferMissingResult(sessionId, data.getString(MediaControlIntent.EXTRA_SESSION_ID));
                    MediaSessionStatus sessionStatus = MediaSessionStatus.fromBundle(data.getBundle(MediaControlIntent.EXTRA_SESSION_STATUS));
                    String itemIdResult = RemotePlaybackClient.inferMissingResult(itemId, data.getString(MediaControlIntent.EXTRA_ITEM_ID));
                    MediaItemStatus itemStatus = MediaItemStatus.fromBundle(data.getBundle(MediaControlIntent.EXTRA_ITEM_STATUS));
                    RemotePlaybackClient.this.adoptSession(sessionIdResult);
                    if (sessionIdResult != null && itemIdResult != null && itemStatus != null) {
                        if (RemotePlaybackClient.DEBUG) {
                            Log.d(RemotePlaybackClient.TAG, "Received result from " + intent.getAction() + ": data=" + RemotePlaybackClient.bundleToString(data) + ", sessionId=" + sessionIdResult + ", sessionStatus=" + sessionStatus + ", itemId=" + itemIdResult + ", itemStatus=" + itemStatus);
                        }
                        callback.onResult(data, sessionIdResult, sessionStatus, itemIdResult, itemStatus);
                        return;
                    }
                }
                RemotePlaybackClient.this.handleInvalidResult(intent, callback, data);
            }

            @Override // android.support.v7.media.MediaRouter.ControlRequestCallback
            public void onError(String error, Bundle data) {
                RemotePlaybackClient.this.handleError(intent, callback, error, data);
            }
        });
    }

    private void performSessionAction(final Intent intent, final String sessionId, Bundle extras, final SessionActionCallback callback) {
        intent.addCategory(MediaControlIntent.CATEGORY_REMOTE_PLAYBACK);
        if (sessionId != null) {
            intent.putExtra(MediaControlIntent.EXTRA_SESSION_ID, sessionId);
        }
        if (extras != null) {
            intent.putExtras(extras);
        }
        logRequest(intent);
        this.mRoute.sendControlRequest(intent, new MediaRouter.ControlRequestCallback() { // from class: android.support.v7.media.RemotePlaybackClient.2
            @Override // android.support.v7.media.MediaRouter.ControlRequestCallback
            public void onResult(Bundle data) {
                boolean equals;
                boolean equals2;
                if (data != null) {
                    String sessionIdResult = RemotePlaybackClient.inferMissingResult(sessionId, data.getString(MediaControlIntent.EXTRA_SESSION_ID));
                    MediaSessionStatus sessionStatus = MediaSessionStatus.fromBundle(data.getBundle(MediaControlIntent.EXTRA_SESSION_STATUS));
                    RemotePlaybackClient.this.adoptSession(sessionIdResult);
                    if (sessionIdResult != null) {
                        if (RemotePlaybackClient.DEBUG) {
                            Log.d(RemotePlaybackClient.TAG, "Received result from " + intent.getAction() + ": data=" + RemotePlaybackClient.bundleToString(data) + ", sessionId=" + sessionIdResult + ", sessionStatus=" + sessionStatus);
                        }
                        try {
                            callback.onResult(data, sessionIdResult, sessionStatus);
                            if (equals) {
                                if (equals2) {
                                    return;
                                }
                                return;
                            }
                            return;
                        } finally {
                            if (intent.getAction().equals(MediaControlIntent.ACTION_END_SESSION) && sessionIdResult.equals(RemotePlaybackClient.this.mSessionId)) {
                                RemotePlaybackClient.this.setSessionId(null);
                            }
                        }
                    }
                }
                RemotePlaybackClient.this.handleInvalidResult(intent, callback, data);
            }

            @Override // android.support.v7.media.MediaRouter.ControlRequestCallback
            public void onError(String error, Bundle data) {
                RemotePlaybackClient.this.handleError(intent, callback, error, data);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void adoptSession(String sessionId) {
        if (sessionId != null) {
            setSessionId(sessionId);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void handleInvalidResult(Intent intent, ActionCallback callback, Bundle data) {
        Log.w(TAG, "Received invalid result data from " + intent.getAction() + ": data=" + bundleToString(data));
        callback.onError(null, 0, data);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void handleError(Intent intent, ActionCallback callback, String error, Bundle data) {
        int code;
        if (data != null) {
            code = data.getInt(MediaControlIntent.EXTRA_ERROR_CODE, 0);
        } else {
            code = 0;
        }
        if (DEBUG) {
            Log.w(TAG, "Received error from " + intent.getAction() + ": error=" + error + ", code=" + code + ", data=" + bundleToString(data));
        }
        callback.onError(error, code, data);
    }

    private void detectFeatures() {
        boolean z = true;
        this.mRouteSupportsRemotePlayback = routeSupportsAction(MediaControlIntent.ACTION_PLAY) && routeSupportsAction(MediaControlIntent.ACTION_SEEK) && routeSupportsAction(MediaControlIntent.ACTION_GET_STATUS) && routeSupportsAction(MediaControlIntent.ACTION_PAUSE) && routeSupportsAction(MediaControlIntent.ACTION_RESUME) && routeSupportsAction(MediaControlIntent.ACTION_STOP);
        this.mRouteSupportsQueuing = this.mRouteSupportsRemotePlayback && routeSupportsAction(MediaControlIntent.ACTION_ENQUEUE) && routeSupportsAction(MediaControlIntent.ACTION_REMOVE);
        if (!this.mRouteSupportsRemotePlayback || !routeSupportsAction(MediaControlIntent.ACTION_START_SESSION) || !routeSupportsAction(MediaControlIntent.ACTION_GET_SESSION_STATUS) || !routeSupportsAction(MediaControlIntent.ACTION_END_SESSION)) {
            z = false;
        }
        this.mRouteSupportsSessionManagement = z;
    }

    private boolean routeSupportsAction(String action) {
        return this.mRoute.supportsControlAction(MediaControlIntent.CATEGORY_REMOTE_PLAYBACK, action);
    }

    private void throwIfRemotePlaybackNotSupported() {
        if (!this.mRouteSupportsRemotePlayback) {
            throw new UnsupportedOperationException("The route does not support remote playback.");
        }
    }

    private void throwIfQueuingNotSupported() {
        if (!this.mRouteSupportsQueuing) {
            throw new UnsupportedOperationException("The route does not support queuing.");
        }
    }

    private void throwIfSessionManagementNotSupported() {
        if (!this.mRouteSupportsSessionManagement) {
            throw new UnsupportedOperationException("The route does not support session management.");
        }
    }

    private void throwIfNoCurrentSession() {
        if (this.mSessionId == null) {
            throw new IllegalStateException("There is no current session.");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static String inferMissingResult(String request, String result) {
        if (result != null) {
            if (request == null || request.equals(result)) {
                return result;
            }
            return null;
        }
        return request;
    }

    private static void logRequest(Intent intent) {
        if (DEBUG) {
            Log.d(TAG, "Sending request: " + intent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static String bundleToString(Bundle bundle) {
        if (bundle != null) {
            bundle.size();
            return bundle.toString();
        }
        return "null";
    }

    /* loaded from: classes.dex */
    private final class StatusReceiver extends BroadcastReceiver {
        public static final String ACTION_ITEM_STATUS_CHANGED = "android.support.v7.media.actions.ACTION_ITEM_STATUS_CHANGED";
        public static final String ACTION_SESSION_STATUS_CHANGED = "android.support.v7.media.actions.ACTION_SESSION_STATUS_CHANGED";

        private StatusReceiver() {
        }

        @Override // android.content.BroadcastReceiver
        public void onReceive(Context context, Intent intent) {
            String sessionId = intent.getStringExtra(MediaControlIntent.EXTRA_SESSION_ID);
            if (sessionId == null || !sessionId.equals(RemotePlaybackClient.this.mSessionId)) {
                Log.w(RemotePlaybackClient.TAG, "Discarding spurious status callback with missing or invalid session id: sessionId=" + sessionId);
                return;
            }
            MediaSessionStatus sessionStatus = MediaSessionStatus.fromBundle(intent.getBundleExtra(MediaControlIntent.EXTRA_SESSION_STATUS));
            String action = intent.getAction();
            if (action.equals(ACTION_ITEM_STATUS_CHANGED)) {
                String itemId = intent.getStringExtra(MediaControlIntent.EXTRA_ITEM_ID);
                if (itemId == null) {
                    Log.w(RemotePlaybackClient.TAG, "Discarding spurious status callback with missing item id.");
                    return;
                }
                MediaItemStatus itemStatus = MediaItemStatus.fromBundle(intent.getBundleExtra(MediaControlIntent.EXTRA_ITEM_STATUS));
                if (itemStatus != null) {
                    if (RemotePlaybackClient.DEBUG) {
                        Log.d(RemotePlaybackClient.TAG, "Received item status callback: sessionId=" + sessionId + ", sessionStatus=" + sessionStatus + ", itemId=" + itemId + ", itemStatus=" + itemStatus);
                    }
                    if (RemotePlaybackClient.this.mStatusCallback != null) {
                        RemotePlaybackClient.this.mStatusCallback.onItemStatusChanged(intent.getExtras(), sessionId, sessionStatus, itemId, itemStatus);
                        return;
                    }
                    return;
                }
                Log.w(RemotePlaybackClient.TAG, "Discarding spurious status callback with missing item status.");
            } else if (action.equals(ACTION_SESSION_STATUS_CHANGED)) {
                if (sessionStatus != null) {
                    if (RemotePlaybackClient.DEBUG) {
                        Log.d(RemotePlaybackClient.TAG, "Received session status callback: sessionId=" + sessionId + ", sessionStatus=" + sessionStatus);
                    }
                    if (RemotePlaybackClient.this.mStatusCallback != null) {
                        RemotePlaybackClient.this.mStatusCallback.onSessionStatusChanged(intent.getExtras(), sessionId, sessionStatus);
                        return;
                    }
                    return;
                }
                Log.w(RemotePlaybackClient.TAG, "Discarding spurious media status callback with missing session status.");
            }
        }
    }

    /* loaded from: classes.dex */
    public static abstract class StatusCallback {
        public void onItemStatusChanged(Bundle data, String sessionId, MediaSessionStatus sessionStatus, String itemId, MediaItemStatus itemStatus) {
        }

        public void onSessionStatusChanged(Bundle data, String sessionId, MediaSessionStatus sessionStatus) {
        }

        public void onSessionChanged(String sessionId) {
        }
    }

    /* loaded from: classes.dex */
    public static abstract class ActionCallback {
        public void onError(String error, int code, Bundle data) {
        }
    }

    /* loaded from: classes.dex */
    public static abstract class ItemActionCallback extends ActionCallback {
        public void onResult(Bundle data, String sessionId, MediaSessionStatus sessionStatus, String itemId, MediaItemStatus itemStatus) {
        }
    }

    /* loaded from: classes.dex */
    public static abstract class SessionActionCallback extends ActionCallback {
        public void onResult(Bundle data, String sessionId, MediaSessionStatus sessionStatus) {
        }
    }
}
