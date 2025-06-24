package com.google.android.gms.ads.internal.overlay;

import android.app.Activity;
import android.content.Context;
import android.graphics.Color;
import android.os.Bundle;
import android.support.v4.view.ViewCompat;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.Window;
import android.webkit.WebChromeClient;
import android.widget.FrameLayout;
import android.widget.RelativeLayout;
import com.google.android.gms.ads.internal.zzo;
import com.google.android.gms.internal.zzex;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzhn;
import com.google.android.gms.internal.zzid;
import com.google.android.gms.internal.zzie;
@zzgd
/* loaded from: classes.dex */
public class zzc extends zzex.zza implements zzl {
    static final int zzzj = Color.argb(0, 0, 0, 0);
    private final Activity mActivity;
    zzid zzoA;
    RelativeLayout zzyG;
    AdOverlayInfoParcel zzzk;
    zzh zzzl;
    C0013zzc zzzm;
    zzj zzzn;
    FrameLayout zzzp;
    WebChromeClient.CustomViewCallback zzzq;
    private boolean zzzv;
    boolean zzzo = false;
    boolean zzzr = false;
    boolean zzzs = false;
    boolean zzzt = false;
    int zzzu = 0;
    private boolean zzzw = false;
    private boolean zzzx = true;

    /* JADX INFO: Access modifiers changed from: private */
    @zzgd
    /* loaded from: classes.dex */
    public static final class zza extends Exception {
        public zza(String str) {
            super(str);
        }
    }

    @zzgd
    /* loaded from: classes.dex */
    static final class zzb extends RelativeLayout {
        zzhn zzqn;

        public zzb(Context context, String str) {
            super(context);
            this.zzqn = new zzhn(context, str);
        }

        @Override // android.view.ViewGroup
        public boolean onInterceptTouchEvent(MotionEvent event) {
            this.zzqn.zzd(event);
            return false;
        }
    }

    @zzgd
    /* renamed from: com.google.android.gms.ads.internal.overlay.zzc$zzc  reason: collision with other inner class name */
    /* loaded from: classes.dex */
    public static class C0013zzc {
        public final int index;
        public final Context zzpH;
        public final ViewGroup zzzA;
        public final ViewGroup.LayoutParams zzzz;

        public C0013zzc(zzid zzidVar) throws zza {
            this.zzzz = zzidVar.getLayoutParams();
            ViewParent parent = zzidVar.getParent();
            this.zzpH = zzidVar.zzgC();
            if (parent == null || !(parent instanceof ViewGroup)) {
                throw new zza("Could not get the parent of the WebView for an overlay.");
            }
            this.zzzA = (ViewGroup) parent;
            this.index = this.zzzA.indexOfChild(zzidVar.getWebView());
            this.zzzA.removeView(zzidVar.getWebView());
            zzidVar.zzB(true);
        }
    }

    public zzc(Activity activity) {
        this.mActivity = activity;
    }

    public void close() {
        this.zzzu = 2;
        this.mActivity.finish();
    }

    @Override // com.google.android.gms.internal.zzex
    public void onBackPressed() {
        this.zzzu = 0;
    }

    @Override // com.google.android.gms.internal.zzex
    public void onCreate(Bundle savedInstanceState) {
        this.zzzr = savedInstanceState != null ? savedInstanceState.getBoolean("com.google.android.gms.ads.internal.overlay.hasResumed", false) : false;
        try {
            this.zzzk = AdOverlayInfoParcel.zzb(this.mActivity.getIntent());
            if (this.zzzk == null) {
                throw new zza("Could not get info for ad overlay.");
            }
            if (this.zzzk.zzpJ.zzGI > 7500000) {
                this.zzzu = 3;
            }
            if (this.mActivity.getIntent() != null) {
                this.zzzx = this.mActivity.getIntent().getBooleanExtra("shouldCallOnOverlayOpened", true);
            }
            if (this.zzzk.zzzN != null) {
                this.zzzs = this.zzzk.zzzN.zzoU;
            } else {
                this.zzzs = false;
            }
            if (savedInstanceState == null) {
                if (this.zzzk.zzzD != null && this.zzzx) {
                    this.zzzk.zzzD.zzaW();
                }
                if (this.zzzk.zzzK != 1 && this.zzzk.zzzC != null) {
                    this.zzzk.zzzC.onAdClicked();
                }
            }
            this.zzyG = new zzb(this.mActivity, this.zzzk.zzzM);
            switch (this.zzzk.zzzK) {
                case 1:
                    zzu(false);
                    return;
                case 2:
                    this.zzzm = new C0013zzc(this.zzzk.zzzE);
                    zzu(false);
                    return;
                case 3:
                    zzu(true);
                    return;
                case 4:
                    if (this.zzzr) {
                        this.zzzu = 3;
                        this.mActivity.finish();
                        return;
                    } else if (zzo.zzbs().zza(this.mActivity, this.zzzk.zzzB, this.zzzk.zzzJ)) {
                        return;
                    } else {
                        this.zzzu = 3;
                        this.mActivity.finish();
                        return;
                    }
                default:
                    throw new zza("Could not determine ad overlay type.");
            }
        } catch (zza e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC(e.getMessage());
            this.zzzu = 3;
            this.mActivity.finish();
        }
    }

    @Override // com.google.android.gms.internal.zzex
    public void onDestroy() {
        if (this.zzzl != null) {
            this.zzzl.destroy();
        }
        if (this.zzoA != null) {
            this.zzyG.removeView(this.zzoA.getWebView());
        }
        zzeu();
    }

    @Override // com.google.android.gms.internal.zzex
    public void onPause() {
        if (this.zzzl != null) {
            this.zzzl.pause();
        }
        zzer();
        if (this.zzoA != null && (!this.mActivity.isFinishing() || this.zzzm == null)) {
            zzo.zzbx().zza(this.zzoA.getWebView());
        }
        zzeu();
    }

    @Override // com.google.android.gms.internal.zzex
    public void onRestart() {
    }

    @Override // com.google.android.gms.internal.zzex
    public void onResume() {
        if (this.zzzk != null && this.zzzk.zzzK == 4) {
            if (this.zzzr) {
                this.zzzu = 3;
                this.mActivity.finish();
            } else {
                this.zzzr = true;
            }
        }
        if (this.zzoA == null || this.zzoA.isDestroyed()) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("The webview does not exit. Ignoring action.");
        } else {
            zzo.zzbx().zzb(this.zzoA.getWebView());
        }
    }

    @Override // com.google.android.gms.internal.zzex
    public void onSaveInstanceState(Bundle outBundle) {
        outBundle.putBoolean("com.google.android.gms.ads.internal.overlay.hasResumed", this.zzzr);
    }

    @Override // com.google.android.gms.internal.zzex
    public void onStart() {
    }

    @Override // com.google.android.gms.internal.zzex
    public void onStop() {
        zzeu();
    }

    public void setRequestedOrientation(int requestedOrientation) {
        this.mActivity.setRequestedOrientation(requestedOrientation);
    }

    public void zza(View view, WebChromeClient.CustomViewCallback customViewCallback) {
        this.zzzp = new FrameLayout(this.mActivity);
        this.zzzp.setBackgroundColor(ViewCompat.MEASURED_STATE_MASK);
        this.zzzp.addView(view, -1, -1);
        this.mActivity.setContentView(this.zzzp);
        zzaE();
        this.zzzq = customViewCallback;
        this.zzzo = true;
    }

    public void zza(boolean z, boolean z2) {
        if (this.zzzn != null) {
            this.zzzn.zza(z, z2);
        }
    }

    @Override // com.google.android.gms.internal.zzex
    public void zzaE() {
        this.zzzv = true;
    }

    public void zzd(int i, int i2, int i3, int i4) {
        if (this.zzzl != null) {
            this.zzzl.zzf(i, i2, i3, i4);
        }
    }

    public void zze(int i, int i2, int i3, int i4) {
        if (this.zzzl == null) {
            this.zzzl = new zzh(this.mActivity, this.zzoA);
            this.zzyG.addView(this.zzzl, 0, new ViewGroup.LayoutParams(-1, -1));
            this.zzzl.zzf(i, i2, i3, i4);
            this.zzoA.zzgF().zzD(false);
        }
    }

    public zzh zzeq() {
        return this.zzzl;
    }

    public void zzer() {
        if (this.zzzk != null && this.zzzo) {
            setRequestedOrientation(this.zzzk.orientation);
        }
        if (this.zzzp != null) {
            this.mActivity.setContentView(this.zzyG);
            zzaE();
            this.zzzp.removeAllViews();
            this.zzzp = null;
        }
        if (this.zzzq != null) {
            this.zzzq.onCustomViewHidden();
            this.zzzq = null;
        }
        this.zzzo = false;
    }

    @Override // com.google.android.gms.ads.internal.overlay.zzl
    public void zzes() {
        this.zzzu = 1;
        this.mActivity.finish();
    }

    public void zzet() {
        this.zzyG.removeView(this.zzzn);
        zzt(true);
    }

    protected void zzeu() {
        if (!this.mActivity.isFinishing() || this.zzzw) {
            return;
        }
        this.zzzw = true;
        if (this.mActivity.isFinishing()) {
            if (this.zzoA != null) {
                zzv(this.zzzu);
                this.zzyG.removeView(this.zzoA.getWebView());
                if (this.zzzm != null) {
                    this.zzoA.setContext(this.zzzm.zzpH);
                    this.zzoA.zzB(false);
                    this.zzzm.zzzA.addView(this.zzoA.getWebView(), this.zzzm.index, this.zzzm.zzzz);
                    this.zzzm = null;
                }
            }
            if (this.zzzk == null || this.zzzk.zzzD == null) {
                return;
            }
            this.zzzk.zzzD.zzaV();
        }
    }

    public void zzev() {
        if (this.zzzt) {
            this.zzzt = false;
            zzew();
        }
    }

    protected void zzew() {
        this.zzoA.zzew();
    }

    public void zzt(boolean z) {
        this.zzzn = new zzj(this.mActivity, z ? 50 : 32, this);
        RelativeLayout.LayoutParams layoutParams = new RelativeLayout.LayoutParams(-2, -2);
        layoutParams.addRule(10);
        layoutParams.addRule(z ? 11 : 9);
        this.zzzn.zza(z, this.zzzk.zzzH);
        this.zzyG.addView(this.zzzn, layoutParams);
    }

    protected void zzu(boolean z) throws zza {
        if (!this.zzzv) {
            this.mActivity.requestWindowFeature(1);
        }
        Window window = this.mActivity.getWindow();
        if (window == null) {
            throw new zza("Invalid activity, no window available.");
        }
        if (!this.zzzs || (this.zzzk.zzzN != null && this.zzzk.zzzN.zzoV)) {
            window.setFlags(1024, 1024);
        }
        boolean zzbU = this.zzzk.zzzE.zzgF().zzbU();
        this.zzzt = false;
        if (zzbU) {
            if (this.zzzk.orientation == zzo.zzbx().zzgq()) {
                this.zzzt = this.mActivity.getResources().getConfiguration().orientation == 1;
            } else if (this.zzzk.orientation == zzo.zzbx().zzgr()) {
                this.zzzt = this.mActivity.getResources().getConfiguration().orientation == 2;
            }
        }
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Delay onShow to next orientation change: " + this.zzzt);
        setRequestedOrientation(this.zzzk.orientation);
        if (zzo.zzbx().zza(window)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzay("Hardware acceleration on the AdActivity window enabled.");
        }
        if (this.zzzs) {
            this.zzyG.setBackgroundColor(zzzj);
        } else {
            this.zzyG.setBackgroundColor(ViewCompat.MEASURED_STATE_MASK);
        }
        this.mActivity.setContentView(this.zzyG);
        zzaE();
        if (z) {
            this.zzoA = zzo.zzbw().zza(this.mActivity, this.zzzk.zzzE.zzaN(), true, zzbU, null, this.zzzk.zzpJ);
            this.zzoA.zzgF().zzb(null, null, this.zzzk.zzzF, this.zzzk.zzzJ, true, this.zzzk.zzzL, null, this.zzzk.zzzE.zzgF().zzgM(), null);
            this.zzoA.zzgF().zza(new zzie.zza() { // from class: com.google.android.gms.ads.internal.overlay.zzc.1
                @Override // com.google.android.gms.internal.zzie.zza
                public void zza(zzid zzidVar, boolean z2) {
                    zzidVar.zzgF().zzgS();
                    zzidVar.zzew();
                }
            });
            if (this.zzzk.zzzf != null) {
                this.zzoA.loadUrl(this.zzzk.zzzf);
            } else if (this.zzzk.zzzI == null) {
                throw new zza("No URL or HTML to display in ad overlay.");
            } else {
                this.zzoA.loadDataWithBaseURL(this.zzzk.zzzG, this.zzzk.zzzI, "text/html", "UTF-8", null);
            }
            if (this.zzzk.zzzE != null) {
                this.zzzk.zzzE.zzb(this);
            }
        } else {
            this.zzoA = this.zzzk.zzzE;
            this.zzoA.setContext(this.mActivity);
        }
        this.zzoA.zza(this);
        ViewParent parent = this.zzoA.getParent();
        if (parent != null && (parent instanceof ViewGroup)) {
            ((ViewGroup) parent).removeView(this.zzoA.getWebView());
        }
        if (this.zzzs) {
            this.zzoA.setBackgroundColor(zzzj);
        }
        this.zzyG.addView(this.zzoA.getWebView(), -1, -1);
        if (!z && !this.zzzt) {
            zzew();
        }
        zzt(zzbU);
        if (this.zzoA.zzgG()) {
            zza(zzbU, true);
        }
    }

    protected void zzv(int i) {
        this.zzoA.zzv(i);
    }
}
