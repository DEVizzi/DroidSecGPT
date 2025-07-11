package android.support.v4.media.session;

import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.media.AudioManager;
import android.media.RemoteControlClient;
import android.os.SystemClock;
import android.support.v4.media.session.MediaSessionCompatApi14;
import android.util.Log;
/* loaded from: classes.dex */
class MediaSessionCompatApi18 {
    private static final long ACTION_SEEK_TO = 256;
    private static final String TAG = "MediaSessionCompatApi18";
    private static boolean sIsMbrPendingIntentSupported = true;

    MediaSessionCompatApi18() {
    }

    public static Object createPlaybackPositionUpdateListener(MediaSessionCompatApi14.Callback callback) {
        return new OnPlaybackPositionUpdateListener(callback);
    }

    public static void registerMediaButtonEventReceiver(Context context, PendingIntent pi, ComponentName cn) {
        AudioManager am = (AudioManager) context.getSystemService("audio");
        if (sIsMbrPendingIntentSupported) {
            try {
                am.registerMediaButtonEventReceiver(pi);
            } catch (NullPointerException e) {
                Log.w(TAG, "Unable to register media button event receiver with PendingIntent, falling back to ComponentName.");
                sIsMbrPendingIntentSupported = false;
            }
        }
        if (!sIsMbrPendingIntentSupported) {
            am.registerMediaButtonEventReceiver(cn);
        }
    }

    public static void unregisterMediaButtonEventReceiver(Context context, PendingIntent pi, ComponentName cn) {
        AudioManager am = (AudioManager) context.getSystemService("audio");
        if (sIsMbrPendingIntentSupported) {
            am.unregisterMediaButtonEventReceiver(pi);
        } else {
            am.unregisterMediaButtonEventReceiver(cn);
        }
    }

    public static void setState(Object rccObj, int state, long position, float speed, long updateTime) {
        long currTime = SystemClock.elapsedRealtime();
        if (state == 3 && position > 0) {
            long diff = 0;
            if (updateTime > 0) {
                diff = currTime - updateTime;
                if (speed > 0.0f && speed != 1.0f) {
                    diff = ((float) diff) * speed;
                }
            }
            position += diff;
        }
        ((RemoteControlClient) rccObj).setPlaybackState(MediaSessionCompatApi14.getRccStateFromState(state), position, speed);
    }

    public static void setTransportControlFlags(Object rccObj, long actions) {
        ((RemoteControlClient) rccObj).setTransportControlFlags(getRccTransportControlFlagsFromActions(actions));
    }

    public static void setOnPlaybackPositionUpdateListener(Object rccObj, Object onPositionUpdateObj) {
        ((RemoteControlClient) rccObj).setPlaybackPositionUpdateListener((RemoteControlClient.OnPlaybackPositionUpdateListener) onPositionUpdateObj);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int getRccTransportControlFlagsFromActions(long actions) {
        int transportControlFlags = MediaSessionCompatApi14.getRccTransportControlFlagsFromActions(actions);
        if ((256 & actions) != 0) {
            return transportControlFlags | 256;
        }
        return transportControlFlags;
    }

    /* loaded from: classes.dex */
    static class OnPlaybackPositionUpdateListener<T extends MediaSessionCompatApi14.Callback> implements RemoteControlClient.OnPlaybackPositionUpdateListener {
        protected final T mCallback;

        public OnPlaybackPositionUpdateListener(T callback) {
            this.mCallback = callback;
        }

        @Override // android.media.RemoteControlClient.OnPlaybackPositionUpdateListener
        public void onPlaybackPositionUpdate(long newPositionMs) {
            this.mCallback.onSeekTo(newPositionMs);
        }
    }
}
