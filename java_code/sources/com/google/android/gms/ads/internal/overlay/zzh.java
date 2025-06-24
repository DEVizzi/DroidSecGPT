package com.google.android.gms.ads.internal.overlay;

import android.content.Context;
import android.media.MediaPlayer;
import android.support.v4.internal.view.SupportMenu;
import android.support.v4.view.InputDeviceCompat;
import android.support.v4.view.ViewCompat;
import android.support.v7.media.MediaRouteProviderProtocol;
import android.text.TextUtils;
import android.view.MotionEvent;
import android.widget.FrameLayout;
import android.widget.TextView;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzid;
import java.util.HashMap;
@zzgd
/* loaded from: classes.dex */
public class zzh extends FrameLayout implements zzg {
    private final zzid zzoA;
    private String zzwC;
    private final FrameLayout zzzO;
    private final zzi zzzP;
    private final zzm zzzQ;
    private TextView zzzR;
    private long zzzS;
    private long zzzT;

    public zzh(Context context, zzid zzidVar) {
        super(context);
        this.zzoA = zzidVar;
        this.zzzO = new FrameLayout(context);
        addView(this.zzzO);
        this.zzzP = new zzi(context);
        this.zzzO.addView(this.zzzP, new FrameLayout.LayoutParams(-1, -1, 17));
        this.zzzR = new TextView(context);
        this.zzzR.setBackgroundColor(ViewCompat.MEASURED_STATE_MASK);
        zzeM();
        this.zzzQ = new zzm(this);
        this.zzzQ.zzeY();
        this.zzzP.zza(this);
    }

    private void zza(String str, String... strArr) {
        HashMap hashMap = new HashMap();
        hashMap.put("event", str);
        int length = strArr.length;
        int i = 0;
        String str2 = null;
        while (i < length) {
            String str3 = strArr[i];
            if (str2 != null) {
                hashMap.put(str2, str3);
                str3 = null;
            }
            i++;
            str2 = str3;
        }
        this.zzoA.zzc("onVideoEvent", hashMap);
    }

    public static void zzd(zzid zzidVar) {
        HashMap hashMap = new HashMap();
        hashMap.put("event", "no_video_view");
        zzidVar.zzc("onVideoEvent", hashMap);
    }

    private void zzeM() {
        if (zzeO()) {
            return;
        }
        this.zzzO.addView(this.zzzR, new FrameLayout.LayoutParams(-1, -1));
        this.zzzO.bringChildToFront(this.zzzR);
    }

    private void zzeN() {
        if (zzeO()) {
            this.zzzO.removeView(this.zzzR);
        }
    }

    private boolean zzeO() {
        return this.zzzR.getParent() != null;
    }

    public void destroy() {
        this.zzzQ.cancel();
        this.zzzP.stop();
    }

    @Override // com.google.android.gms.ads.internal.overlay.zzg
    public void onPaused() {
        zza("pause", new String[0]);
    }

    @Override // com.google.android.gms.ads.internal.overlay.zzg
    public void onPrepared(MediaPlayer mediaPlayer) {
        if (this.zzzT == 0) {
            zza("canplaythrough", "duration", String.valueOf(mediaPlayer.getDuration() / 1000.0f), "videoWidth", String.valueOf(mediaPlayer.getVideoWidth()), "videoHeight", String.valueOf(mediaPlayer.getVideoHeight()));
        }
    }

    public void pause() {
        this.zzzP.pause();
    }

    public void play() {
        this.zzzP.play();
    }

    public void seekTo(int millis) {
        this.zzzP.seekTo(millis);
    }

    public void zza(float f) {
        this.zzzP.zza(f);
    }

    public void zzah(String str) {
        this.zzwC = str;
    }

    public void zzc(MotionEvent motionEvent) {
        this.zzzP.dispatchTouchEvent(motionEvent);
    }

    @Override // com.google.android.gms.ads.internal.overlay.zzg
    public void zzeD() {
    }

    @Override // com.google.android.gms.ads.internal.overlay.zzg
    public void zzeE() {
    }

    @Override // com.google.android.gms.ads.internal.overlay.zzg
    public void zzeF() {
        zza("ended", new String[0]);
    }

    @Override // com.google.android.gms.ads.internal.overlay.zzg
    public void zzeG() {
        zzeM();
        this.zzzT = this.zzzS;
    }

    public void zzeH() {
        if (TextUtils.isEmpty(this.zzwC)) {
            zza("no_src", new String[0]);
        } else {
            this.zzzP.setVideoPath(this.zzwC);
        }
    }

    public void zzeI() {
        this.zzzP.zzeI();
    }

    public void zzeJ() {
        this.zzzP.zzeJ();
    }

    public void zzeK() {
        TextView textView = new TextView(this.zzzP.getContext());
        textView.setText("AdMob");
        textView.setTextColor(SupportMenu.CATEGORY_MASK);
        textView.setBackgroundColor(InputDeviceCompat.SOURCE_ANY);
        this.zzzO.addView(textView, new FrameLayout.LayoutParams(-2, -2, 17));
        this.zzzO.bringChildToFront(textView);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zzeL() {
        long currentPosition = this.zzzP.getCurrentPosition();
        if (this.zzzS == currentPosition || currentPosition <= 0) {
            return;
        }
        zzeN();
        zza("timeupdate", "time", String.valueOf(((float) currentPosition) / 1000.0f));
        this.zzzS = currentPosition;
    }

    public void zzf(int i, int i2, int i3, int i4) {
        if (i3 == 0 || i4 == 0) {
            return;
        }
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(i3 + 2, i4 + 2);
        layoutParams.setMargins(i - 1, i2 - 1, 0, 0);
        this.zzzO.setLayoutParams(layoutParams);
        requestLayout();
    }

    @Override // com.google.android.gms.ads.internal.overlay.zzg
    public void zzg(String str, String str2) {
        zza(MediaRouteProviderProtocol.SERVICE_DATA_ERROR, "what", str, "extra", str2);
    }
}
