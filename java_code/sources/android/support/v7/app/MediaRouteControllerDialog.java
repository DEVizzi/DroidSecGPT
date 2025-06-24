package android.support.v7.app;

import android.app.Dialog;
import android.content.Context;
import android.content.IntentSender;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.RemoteException;
import android.support.v4.media.MediaDescriptionCompat;
import android.support.v4.media.MediaMetadataCompat;
import android.support.v4.media.session.MediaControllerCompat;
import android.support.v4.media.session.MediaSessionCompat;
import android.support.v4.media.session.PlaybackStateCompat;
import android.support.v7.media.MediaRouteSelector;
import android.support.v7.media.MediaRouter;
import android.support.v7.mediarouter.R;
import android.text.TextUtils;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;
/* loaded from: classes.dex */
public class MediaRouteControllerDialog extends Dialog {
    private static final String TAG = "MediaRouteControllerDialog";
    private ImageView mArtView;
    private boolean mAttachedToWindow;
    private final MediaRouterCallback mCallback;
    private View mControlView;
    private MediaControllerCallback mControllerCallback;
    private boolean mCreated;
    private Drawable mCurrentIconDrawable;
    private MediaDescriptionCompat mDescription;
    private Button mDisconnectButton;
    private MediaControllerCompat mMediaController;
    private Drawable mMediaRouteConnectingDrawable;
    private Drawable mMediaRouteOnDrawable;
    private ImageButton mPlayPauseButton;
    private final MediaRouter.RouteInfo mRoute;
    private TextView mRouteNameView;
    private final MediaRouter mRouter;
    private ImageButton mSettingsButton;
    private Drawable mSettingsDrawable;
    private PlaybackStateCompat mState;
    private Button mStopCastingButton;
    private TextView mSubtitleView;
    private TextView mTitleView;
    private View mTitlesWrapper;

    public MediaRouteControllerDialog(Context context) {
        this(context, 0);
    }

    public MediaRouteControllerDialog(Context context, int theme) {
        super(MediaRouterThemeHelper.createThemedContext(context), theme);
        Context context2 = getContext();
        this.mControllerCallback = new MediaControllerCallback();
        this.mRouter = MediaRouter.getInstance(context2);
        this.mCallback = new MediaRouterCallback();
        this.mRoute = this.mRouter.getSelectedRoute();
        setMediaSession(this.mRouter.getMediaSessionToken());
    }

    public MediaRouter.RouteInfo getRoute() {
        return this.mRoute;
    }

    public View onCreateMediaControlView(Bundle savedInstanceState) {
        return null;
    }

    public View getMediaControlView() {
        return this.mControlView;
    }

    private void setMediaSession(MediaSessionCompat.Token sessionToken) {
        if (this.mMediaController != null) {
            this.mMediaController.unregisterCallback(this.mControllerCallback);
            this.mMediaController = null;
        }
        if (sessionToken != null && this.mAttachedToWindow) {
            try {
                this.mMediaController = new MediaControllerCompat(getContext(), sessionToken);
            } catch (RemoteException e) {
                Log.e(TAG, "Error creating media controller in setMediaSession.", e);
            }
            if (this.mMediaController != null) {
                this.mMediaController.registerCallback(this.mControllerCallback);
            }
            MediaMetadataCompat metadata = this.mMediaController == null ? null : this.mMediaController.getMetadata();
            this.mDescription = metadata == null ? null : metadata.getDescription();
            this.mState = this.mMediaController != null ? this.mMediaController.getPlaybackState() : null;
            update();
        }
    }

    public MediaSessionCompat.Token getMediaSession() {
        if (this.mMediaController == null) {
            return null;
        }
        return this.mMediaController.getSessionToken();
    }

    @Override // android.app.Dialog
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().requestFeature(1);
        setContentView(R.layout.mr_media_route_controller_material_dialog_b);
        ClickListener listener = new ClickListener();
        this.mDisconnectButton = (Button) findViewById(R.id.disconnect);
        this.mDisconnectButton.setOnClickListener(listener);
        this.mStopCastingButton = (Button) findViewById(R.id.stop);
        this.mStopCastingButton.setOnClickListener(listener);
        this.mSettingsButton = (ImageButton) findViewById(R.id.settings);
        this.mSettingsButton.setOnClickListener(listener);
        this.mArtView = (ImageView) findViewById(R.id.art);
        this.mTitleView = (TextView) findViewById(R.id.title);
        this.mSubtitleView = (TextView) findViewById(R.id.subtitle);
        this.mTitlesWrapper = findViewById(R.id.text_wrapper);
        this.mPlayPauseButton = (ImageButton) findViewById(R.id.play_pause);
        this.mPlayPauseButton.setOnClickListener(listener);
        this.mRouteNameView = (TextView) findViewById(R.id.route_name);
        this.mCreated = true;
        if (update()) {
            this.mControlView = onCreateMediaControlView(savedInstanceState);
            FrameLayout controlFrame = (FrameLayout) findViewById(R.id.media_route_control_frame);
            if (this.mControlView != null) {
                controlFrame.findViewById(R.id.default_control_frame).setVisibility(8);
                controlFrame.addView(this.mControlView);
            }
        }
    }

    @Override // android.app.Dialog, android.view.Window.Callback
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.mAttachedToWindow = true;
        this.mRouter.addCallback(MediaRouteSelector.EMPTY, this.mCallback, 2);
        setMediaSession(this.mRouter.getMediaSessionToken());
    }

    @Override // android.app.Dialog, android.view.Window.Callback
    public void onDetachedFromWindow() {
        this.mRouter.removeCallback(this.mCallback);
        setMediaSession(null);
        this.mAttachedToWindow = false;
        super.onDetachedFromWindow();
    }

    @Override // android.app.Dialog, android.view.KeyEvent.Callback
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode == 25 || keyCode == 24) {
            this.mRoute.requestUpdateVolume(keyCode == 25 ? -1 : 1);
            return true;
        }
        return super.onKeyDown(keyCode, event);
    }

    @Override // android.app.Dialog, android.view.KeyEvent.Callback
    public boolean onKeyUp(int keyCode, KeyEvent event) {
        if (keyCode == 25 || keyCode == 24) {
            return true;
        }
        return super.onKeyUp(keyCode, event);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean update() {
        if (!this.mRoute.isSelected() || this.mRoute.isDefault()) {
            dismiss();
            return false;
        } else if (!this.mCreated) {
            return false;
        } else {
            this.mRouteNameView.setText(this.mRoute.getName());
            if (this.mRoute.canDisconnect()) {
                this.mDisconnectButton.setVisibility(0);
            } else {
                this.mDisconnectButton.setVisibility(8);
            }
            if (this.mRoute.getSettingsIntent() != null) {
                this.mSettingsButton.setVisibility(0);
            } else {
                this.mSettingsButton.setVisibility(8);
            }
            if (this.mControlView == null) {
                if (this.mDescription != null) {
                    if (this.mDescription.getIconBitmap() != null) {
                        this.mArtView.setImageBitmap(this.mDescription.getIconBitmap());
                        this.mArtView.setVisibility(0);
                    } else if (this.mDescription.getIconUri() != null) {
                        this.mArtView.setImageURI(this.mDescription.getIconUri());
                        this.mArtView.setVisibility(0);
                    } else {
                        this.mArtView.setImageDrawable(null);
                        this.mArtView.setVisibility(8);
                    }
                    boolean haveText = false;
                    CharSequence text = this.mDescription.getTitle();
                    if (!TextUtils.isEmpty(text)) {
                        this.mTitleView.setText(text);
                        haveText = true;
                    } else {
                        this.mTitleView.setText((CharSequence) null);
                        this.mTitleView.setVisibility(8);
                    }
                    if (!TextUtils.isEmpty(this.mDescription.getSubtitle())) {
                        this.mSubtitleView.setText(this.mDescription.getSubtitle());
                        haveText = true;
                    } else {
                        this.mSubtitleView.setText((CharSequence) null);
                        this.mSubtitleView.setVisibility(8);
                    }
                    if (!haveText) {
                        this.mTitlesWrapper.setVisibility(8);
                    } else {
                        this.mTitlesWrapper.setVisibility(0);
                    }
                } else {
                    this.mArtView.setVisibility(8);
                    this.mTitlesWrapper.setVisibility(8);
                }
                if (this.mState != null) {
                    boolean isPlaying = this.mState.getState() == 6 || this.mState.getState() == 3;
                    boolean supportsPlay = (this.mState.getActions() & 516) != 0;
                    boolean supportsPause = (this.mState.getActions() & 514) != 0;
                    if (isPlaying && supportsPause) {
                        this.mPlayPauseButton.setVisibility(0);
                        this.mPlayPauseButton.setImageResource(MediaRouterThemeHelper.getThemeResource(getContext(), R.attr.mediaRoutePauseDrawable));
                        this.mPlayPauseButton.setContentDescription(getContext().getResources().getText(R.string.mr_media_route_controller_pause));
                    } else if (!isPlaying && supportsPlay) {
                        this.mPlayPauseButton.setVisibility(0);
                        this.mPlayPauseButton.setImageResource(MediaRouterThemeHelper.getThemeResource(getContext(), R.attr.mediaRoutePlayDrawable));
                        this.mPlayPauseButton.setContentDescription(getContext().getResources().getText(R.string.mr_media_route_controller_play));
                    } else {
                        this.mPlayPauseButton.setVisibility(8);
                    }
                } else {
                    this.mPlayPauseButton.setVisibility(8);
                }
            }
            return true;
        }
    }

    private Drawable getIconDrawable() {
        if (this.mRoute.isConnecting()) {
            if (this.mMediaRouteConnectingDrawable == null) {
                this.mMediaRouteConnectingDrawable = MediaRouterThemeHelper.getThemeDrawable(getContext(), R.attr.mediaRouteConnectingDrawable);
            }
            return this.mMediaRouteConnectingDrawable;
        }
        if (this.mMediaRouteOnDrawable == null) {
            this.mMediaRouteOnDrawable = MediaRouterThemeHelper.getThemeDrawable(getContext(), R.attr.mediaRouteOnDrawable);
        }
        return this.mMediaRouteOnDrawable;
    }

    /* loaded from: classes.dex */
    private final class MediaRouterCallback extends MediaRouter.Callback {
        private MediaRouterCallback() {
        }

        @Override // android.support.v7.media.MediaRouter.Callback
        public void onRouteUnselected(MediaRouter router, MediaRouter.RouteInfo route) {
            MediaRouteControllerDialog.this.update();
        }

        @Override // android.support.v7.media.MediaRouter.Callback
        public void onRouteChanged(MediaRouter router, MediaRouter.RouteInfo route) {
            MediaRouteControllerDialog.this.update();
        }

        @Override // android.support.v7.media.MediaRouter.Callback
        public void onRouteVolumeChanged(MediaRouter router, MediaRouter.RouteInfo route) {
            if (route == MediaRouteControllerDialog.this.mRoute) {
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public final class MediaControllerCallback extends MediaControllerCompat.Callback {
        private MediaControllerCallback() {
        }

        @Override // android.support.v4.media.session.MediaControllerCompat.Callback
        public void onSessionDestroyed() {
            if (MediaRouteControllerDialog.this.mMediaController != null) {
                MediaRouteControllerDialog.this.mMediaController.unregisterCallback(MediaRouteControllerDialog.this.mControllerCallback);
                MediaRouteControllerDialog.this.mMediaController = null;
            }
        }

        @Override // android.support.v4.media.session.MediaControllerCompat.Callback
        public void onPlaybackStateChanged(PlaybackStateCompat state) {
            MediaRouteControllerDialog.this.mState = state;
            MediaRouteControllerDialog.this.update();
        }

        @Override // android.support.v4.media.session.MediaControllerCompat.Callback
        public void onMetadataChanged(MediaMetadataCompat metadata) {
            MediaRouteControllerDialog.this.mDescription = metadata == null ? null : metadata.getDescription();
            MediaRouteControllerDialog.this.update();
        }
    }

    /* loaded from: classes.dex */
    private final class ClickListener implements View.OnClickListener {
        private ClickListener() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View v) {
            IntentSender is;
            int id = v.getId();
            if (id == R.id.stop || id == R.id.disconnect) {
                if (MediaRouteControllerDialog.this.mRoute.isSelected()) {
                    MediaRouteControllerDialog.this.mRouter.unselect(id == R.id.stop ? 2 : 1);
                }
                MediaRouteControllerDialog.this.dismiss();
            } else if (id == R.id.play_pause) {
                if (MediaRouteControllerDialog.this.mMediaController != null && MediaRouteControllerDialog.this.mState != null) {
                    if (MediaRouteControllerDialog.this.mState.getState() == 3) {
                        MediaRouteControllerDialog.this.mMediaController.getTransportControls().pause();
                    } else {
                        MediaRouteControllerDialog.this.mMediaController.getTransportControls().play();
                    }
                }
            } else if (id == R.id.settings && (is = MediaRouteControllerDialog.this.mRoute.getSettingsIntent()) != null) {
                try {
                    is.sendIntent(null, 0, null, null, null);
                    MediaRouteControllerDialog.this.dismiss();
                } catch (Exception e) {
                    Log.e(MediaRouteControllerDialog.TAG, "Error opening route settings.", e);
                }
            }
        }
    }
}
