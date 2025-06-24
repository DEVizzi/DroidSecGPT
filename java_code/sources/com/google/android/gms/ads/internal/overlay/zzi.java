package com.google.android.gms.ads.internal.overlay;

import android.content.Context;
import android.media.AudioManager;
import android.media.MediaPlayer;
import android.net.Uri;
import android.os.Build;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import com.google.android.gms.ads.internal.zzo;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzhl;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
@zzgd
/* loaded from: classes.dex */
public class zzi extends SurfaceView implements AudioManager.OnAudioFocusChangeListener, MediaPlayer.OnBufferingUpdateListener, MediaPlayer.OnCompletionListener, MediaPlayer.OnErrorListener, MediaPlayer.OnInfoListener, MediaPlayer.OnPreparedListener, MediaPlayer.OnVideoSizeChangedListener, SurfaceHolder.Callback {
    private static final Map<Integer, String> zzzU = new HashMap();
    private int zzAa;
    private int zzAb;
    private int zzAc;
    private int zzAd;
    private int zzAe;
    private float zzAf;
    private boolean zzAg;
    private boolean zzAh;
    private int zzAi;
    private zzg zzAj;
    private int zzzV;
    private int zzzW;
    private SurfaceHolder zzzX;
    private MediaPlayer zzzY;
    private Uri zzzZ;

    static {
        zzzU.put(-1004, "MEDIA_ERROR_IO");
        zzzU.put(-1007, "MEDIA_ERROR_MALFORMED");
        zzzU.put(-1010, "MEDIA_ERROR_UNSUPPORTED");
        zzzU.put(-110, "MEDIA_ERROR_TIMED_OUT");
        zzzU.put(100, "MEDIA_ERROR_SERVER_DIED");
        zzzU.put(1, "MEDIA_ERROR_UNKNOWN");
        zzzU.put(1, "MEDIA_INFO_UNKNOWN");
        zzzU.put(700, "MEDIA_INFO_VIDEO_TRACK_LAGGING");
        zzzU.put(3, "MEDIA_INFO_VIDEO_RENDERING_START");
        zzzU.put(701, "MEDIA_INFO_BUFFERING_START");
        zzzU.put(702, "MEDIA_INFO_BUFFERING_END");
        zzzU.put(800, "MEDIA_INFO_BAD_INTERLEAVING");
        zzzU.put(801, "MEDIA_INFO_NOT_SEEKABLE");
        zzzU.put(802, "MEDIA_INFO_METADATA_UPDATE");
        zzzU.put(901, "MEDIA_INFO_UNSUPPORTED_SUBTITLE");
        zzzU.put(902, "MEDIA_INFO_SUBTITLE_TIMED_OUT");
    }

    public zzi(Context context) {
        super(context);
        this.zzzV = 0;
        this.zzzW = 0;
        this.zzAf = 1.0f;
        getHolder().addCallback(this);
        if (Build.VERSION.SDK_INT < 11) {
            getHolder().setType(3);
        }
    }

    private void zzb(float f) {
        if (this.zzzY == null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("AdVideoView setMediaPlayerVolume() called before onPrepared().");
            return;
        }
        try {
            this.zzzY.setVolume(f, f);
        } catch (IllegalStateException e) {
        }
    }

    private void zzeP() {
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("AdVideoView init MediaPlayer");
        if (this.zzzZ == null || this.zzzX == null) {
            return;
        }
        zzv(false);
        try {
            this.zzzY = new MediaPlayer();
            this.zzzY.setOnBufferingUpdateListener(this);
            this.zzzY.setOnCompletionListener(this);
            this.zzzY.setOnErrorListener(this);
            this.zzzY.setOnInfoListener(this);
            this.zzzY.setOnPreparedListener(this);
            this.zzzY.setOnVideoSizeChangedListener(this);
            this.zzAe = 0;
            this.zzzY.setDataSource(getContext(), this.zzzZ);
            this.zzzY.setDisplay(this.zzzX);
            this.zzzY.setAudioStreamType(3);
            this.zzzY.setScreenOnWhilePlaying(true);
            this.zzzY.prepareAsync();
            this.zzzV = 1;
        } catch (IOException | IllegalArgumentException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Failed to initialize MediaPlayer at " + this.zzzZ, e);
            onError(this.zzzY, 1, 0);
        }
    }

    private void zzeQ() {
        if (!zzeT() || this.zzzW == 3) {
            return;
        }
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("AdVideoView nudging MediaPlayer");
        this.zzzY.start();
        int currentPosition = this.zzzY.getCurrentPosition();
        long currentTimeMillis = zzo.zzbz().currentTimeMillis();
        while (zzeT() && this.zzzY.getCurrentPosition() == currentPosition && zzo.zzbz().currentTimeMillis() - currentTimeMillis <= 250) {
        }
        this.zzzY.pause();
    }

    private void zzeR() {
        AudioManager zzeX = zzeX();
        if (zzeX == null || this.zzAh) {
            return;
        }
        if (zzeX.requestAudioFocus(this, 3, 2) == 1) {
            zzeU();
        } else {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("AdVideoView audio focus request failed");
        }
    }

    private void zzeS() {
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("AdVideoView abandon audio focus");
        AudioManager zzeX = zzeX();
        if (zzeX == null || !this.zzAh) {
            return;
        }
        if (zzeX.abandonAudioFocus(this) == 1) {
            this.zzAh = false;
        } else {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("AdVideoView abandon audio focus failed");
        }
    }

    private boolean zzeT() {
        return (this.zzzY == null || this.zzzV == -1 || this.zzzV == 0 || this.zzzV == 1) ? false : true;
    }

    private void zzeU() {
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("AdVideoView audio focus gained");
        this.zzAh = true;
        zzeW();
    }

    private void zzeV() {
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("AdVideoView audio focus lost");
        this.zzAh = false;
        zzeW();
    }

    private void zzeW() {
        if (this.zzAg || !this.zzAh) {
            zzb(0.0f);
        } else {
            zzb(this.zzAf);
        }
    }

    private AudioManager zzeX() {
        return (AudioManager) getContext().getSystemService("audio");
    }

    private void zzv(boolean z) {
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("AdVideoView release");
        if (this.zzzY != null) {
            this.zzzY.reset();
            this.zzzY.release();
            this.zzzY = null;
            this.zzzV = 0;
            if (z) {
                this.zzzW = 0;
            }
            zzeS();
        }
    }

    public int getCurrentPosition() {
        if (zzeT()) {
            return this.zzzY.getCurrentPosition();
        }
        return 0;
    }

    @Override // android.media.AudioManager.OnAudioFocusChangeListener
    public void onAudioFocusChange(int focusChange) {
        if (focusChange > 0) {
            zzeU();
        } else if (focusChange < 0) {
            zzeV();
        }
    }

    @Override // android.media.MediaPlayer.OnBufferingUpdateListener
    public void onBufferingUpdate(MediaPlayer mp, int percent) {
        this.zzAe = percent;
    }

    @Override // android.media.MediaPlayer.OnCompletionListener
    public void onCompletion(MediaPlayer mp) {
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("AdVideoView completion");
        this.zzzV = 5;
        this.zzzW = 5;
        zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.ads.internal.overlay.zzi.2
            @Override // java.lang.Runnable
            public void run() {
                if (zzi.this.zzAj != null) {
                    zzi.this.zzAj.zzeF();
                }
            }
        });
    }

    @Override // android.media.MediaPlayer.OnErrorListener
    public boolean onError(MediaPlayer mp, int what, int extra) {
        final String str = zzzU.get(Integer.valueOf(what));
        final String str2 = zzzU.get(Integer.valueOf(extra));
        com.google.android.gms.ads.internal.util.client.zzb.zzaC("AdVideoView MediaPlayer error: " + str + ":" + str2);
        this.zzzV = -1;
        this.zzzW = -1;
        zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.ads.internal.overlay.zzi.3
            @Override // java.lang.Runnable
            public void run() {
                if (zzi.this.zzAj != null) {
                    zzi.this.zzAj.zzg(str, str2);
                }
            }
        });
        return true;
    }

    @Override // android.media.MediaPlayer.OnInfoListener
    public boolean onInfo(MediaPlayer mp, int what, int extra) {
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("AdVideoView MediaPlayer info: " + zzzU.get(Integer.valueOf(what)) + ":" + zzzU.get(Integer.valueOf(extra)));
        return true;
    }

    @Override // android.view.SurfaceView, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int defaultSize = getDefaultSize(this.zzAa, widthMeasureSpec);
        int defaultSize2 = getDefaultSize(this.zzAb, heightMeasureSpec);
        if (this.zzAa > 0 && this.zzAb > 0) {
            int mode = View.MeasureSpec.getMode(widthMeasureSpec);
            int size = View.MeasureSpec.getSize(widthMeasureSpec);
            int mode2 = View.MeasureSpec.getMode(heightMeasureSpec);
            defaultSize2 = View.MeasureSpec.getSize(heightMeasureSpec);
            if (mode == 1073741824 && mode2 == 1073741824) {
                if (this.zzAa * defaultSize2 < this.zzAb * size) {
                    defaultSize = (this.zzAa * defaultSize2) / this.zzAb;
                } else if (this.zzAa * defaultSize2 > this.zzAb * size) {
                    defaultSize2 = (this.zzAb * size) / this.zzAa;
                    defaultSize = size;
                } else {
                    defaultSize = size;
                }
            } else if (mode == 1073741824) {
                int i = (this.zzAb * size) / this.zzAa;
                if (mode2 != Integer.MIN_VALUE || i <= defaultSize2) {
                    defaultSize2 = i;
                    defaultSize = size;
                } else {
                    defaultSize = size;
                }
            } else if (mode2 == 1073741824) {
                defaultSize = (this.zzAa * defaultSize2) / this.zzAb;
                if (mode == Integer.MIN_VALUE && defaultSize > size) {
                    defaultSize = size;
                }
            } else {
                int i2 = this.zzAa;
                int i3 = this.zzAb;
                if (mode2 != Integer.MIN_VALUE || i3 <= defaultSize2) {
                    defaultSize2 = i3;
                    defaultSize = i2;
                } else {
                    defaultSize = (this.zzAa * defaultSize2) / this.zzAb;
                }
                if (mode == Integer.MIN_VALUE && defaultSize > size) {
                    defaultSize2 = (this.zzAb * size) / this.zzAa;
                    defaultSize = size;
                }
            }
        }
        setMeasuredDimension(defaultSize, defaultSize2);
    }

    @Override // android.media.MediaPlayer.OnPreparedListener
    public void onPrepared(final MediaPlayer mediaPlayer) {
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("AdVideoView prepared");
        this.zzzV = 2;
        zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.ads.internal.overlay.zzi.1
            @Override // java.lang.Runnable
            public void run() {
                if (zzi.this.zzAj != null) {
                    zzi.this.zzAj.onPrepared(mediaPlayer);
                }
            }
        });
        this.zzAa = mediaPlayer.getVideoWidth();
        this.zzAb = mediaPlayer.getVideoHeight();
        if (this.zzAi != 0) {
            seekTo(this.zzAi);
        }
        zzeQ();
        if (this.zzAa != 0 && this.zzAb != 0) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaA("AdVideoView stream dimensions: " + this.zzAa + " x " + this.zzAb);
            getHolder().setFixedSize(this.zzAa, this.zzAb);
            if (this.zzAc == this.zzAa && this.zzAd == this.zzAb && this.zzzW == 3) {
                play();
            }
        } else if (this.zzzW == 3) {
            play();
        }
        zzeR();
        zzeW();
    }

    @Override // android.media.MediaPlayer.OnVideoSizeChangedListener
    public void onVideoSizeChanged(MediaPlayer mp, int width, int height) {
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("AdVideoView size changed: " + width + " x " + height);
        this.zzAa = mp.getVideoWidth();
        this.zzAb = mp.getVideoHeight();
        if (this.zzAa == 0 || this.zzAb == 0) {
            return;
        }
        getHolder().setFixedSize(this.zzAa, this.zzAb);
        requestLayout();
    }

    public void pause() {
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("AdVideoView pause");
        if (zzeT() && this.zzzY.isPlaying()) {
            this.zzzY.pause();
            this.zzzV = 4;
            zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.ads.internal.overlay.zzi.7
                @Override // java.lang.Runnable
                public void run() {
                    if (zzi.this.zzAj != null) {
                        zzi.this.zzAj.onPaused();
                    }
                }
            });
        }
        this.zzzW = 4;
    }

    public void play() {
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("AdVideoView play");
        if (zzeT()) {
            this.zzzY.start();
            this.zzzV = 3;
            zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.ads.internal.overlay.zzi.6
                @Override // java.lang.Runnable
                public void run() {
                    if (zzi.this.zzAj != null) {
                        zzi.this.zzAj.zzeE();
                    }
                }
            });
        }
        this.zzzW = 3;
    }

    public void seekTo(int millis) {
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("AdVideoView seek " + millis);
        if (!zzeT()) {
            this.zzAi = millis;
            return;
        }
        this.zzzY.seekTo(millis);
        this.zzAi = 0;
    }

    public void setVideoPath(String path) {
        setVideoURI(Uri.parse(path));
    }

    public void setVideoURI(Uri uri) {
        this.zzzZ = uri;
        this.zzAi = 0;
        zzeP();
        requestLayout();
        invalidate();
    }

    public void stop() {
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("AdVideoView stop");
        if (this.zzzY != null) {
            this.zzzY.stop();
            this.zzzY.release();
            this.zzzY = null;
            this.zzzV = 0;
            this.zzzW = 0;
            zzeS();
        }
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceChanged(SurfaceHolder holder, int format, int w, int h) {
        boolean z = true;
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("AdVideoView surface changed");
        this.zzAc = w;
        this.zzAd = h;
        boolean z2 = this.zzzW == 3;
        if (this.zzAa != w || this.zzAb != h) {
            z = false;
        }
        if (this.zzzY != null && z2 && z) {
            if (this.zzAi != 0) {
                seekTo(this.zzAi);
            }
            play();
        }
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceCreated(SurfaceHolder holder) {
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("AdVideoView surface created");
        this.zzzX = holder;
        zzeP();
        zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.ads.internal.overlay.zzi.4
            @Override // java.lang.Runnable
            public void run() {
                if (zzi.this.zzAj != null) {
                    zzi.this.zzAj.zzeD();
                }
            }
        });
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceDestroyed(SurfaceHolder holder) {
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("AdVideoView surface destroyed");
        if (this.zzzY != null && this.zzAi == 0) {
            this.zzAi = this.zzzY.getCurrentPosition();
        }
        this.zzzX = null;
        zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.ads.internal.overlay.zzi.5
            @Override // java.lang.Runnable
            public void run() {
                if (zzi.this.zzAj != null) {
                    zzi.this.zzAj.onPaused();
                    zzi.this.zzAj.zzeG();
                }
            }
        });
        zzv(true);
    }

    @Override // android.view.View
    public String toString() {
        return getClass().getName() + "@" + Integer.toHexString(hashCode());
    }

    public void zza(float f) {
        this.zzAf = f;
        zzeW();
    }

    public void zza(zzg zzgVar) {
        this.zzAj = zzgVar;
    }

    public void zzeI() {
        this.zzAg = true;
        zzeW();
    }

    public void zzeJ() {
        this.zzAg = false;
        zzeW();
    }
}
