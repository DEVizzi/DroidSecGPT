package com.google.android.gms.internal;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.MutableContextWrapper;
import android.graphics.Canvas;
import android.net.Uri;
import android.os.Build;
import android.support.v7.internal.widget.ActivityChooserView;
import android.util.DisplayMetrics;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.WindowManager;
import android.webkit.DownloadListener;
import android.webkit.ValueCallback;
import android.webkit.WebSettings;
import android.webkit.WebView;
import com.google.android.gms.ads.internal.client.AdSizeParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.drive.DriveFile;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONException;
import org.json.JSONObject;
@zzgd
/* loaded from: classes.dex */
public class zzig extends WebView implements ViewTreeObserver.OnGlobalLayoutListener, DownloadListener, zzid {
    private final zzie zzBd;
    private Boolean zzFO;
    private final zza zzHo;
    private com.google.android.gms.ads.internal.overlay.zzc zzHp;
    private boolean zzHq;
    private boolean zzHr;
    private boolean zzHs;
    private boolean zzHt;
    private boolean zzHu;
    private int zzHv;
    private com.google.android.gms.ads.internal.overlay.zzc zzHw;
    boolean zzHx;
    private final VersionInfoParcel zzoM;
    private final WindowManager zzqF;
    private final Object zzqt;
    private final zzan zzvA;
    private AdSizeParcel zzxT;
    private int zzyW;
    private int zzyX;
    private int zzyZ;
    private int zzza;

    @zzgd
    /* loaded from: classes.dex */
    public static class zza extends MutableContextWrapper {
        private Activity zzHy;
        private Context zzHz;
        private Context zzqw;

        public zza(Context context) {
            super(context);
            setBaseContext(context);
        }

        @Override // android.content.ContextWrapper, android.content.Context
        public Object getSystemService(String service) {
            return this.zzHz.getSystemService(service);
        }

        @Override // android.content.MutableContextWrapper
        public void setBaseContext(Context base) {
            this.zzqw = base.getApplicationContext();
            this.zzHy = base instanceof Activity ? (Activity) base : null;
            this.zzHz = base;
            super.setBaseContext(this.zzqw);
        }

        @Override // android.content.ContextWrapper, android.content.Context
        public void startActivity(Intent intent) {
            if (this.zzHy != null && !zzlk.isAtLeastL()) {
                this.zzHy.startActivity(intent);
                return;
            }
            intent.setFlags(DriveFile.MODE_READ_ONLY);
            this.zzqw.startActivity(intent);
        }

        public Activity zzgB() {
            return this.zzHy;
        }

        public Context zzgC() {
            return this.zzHz;
        }
    }

    protected zzig(zza zzaVar, AdSizeParcel adSizeParcel, boolean z, boolean z2, zzan zzanVar, VersionInfoParcel versionInfoParcel) {
        super(zzaVar);
        this.zzqt = new Object();
        this.zzyX = -1;
        this.zzyW = -1;
        this.zzyZ = -1;
        this.zzza = -1;
        this.zzHo = zzaVar;
        this.zzxT = adSizeParcel;
        this.zzHs = z;
        this.zzHu = false;
        this.zzHv = -1;
        this.zzvA = zzanVar;
        this.zzoM = versionInfoParcel;
        this.zzqF = (WindowManager) getContext().getSystemService("window");
        setBackgroundColor(0);
        WebSettings settings = getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setSavePassword(false);
        settings.setSupportMultipleWindows(true);
        settings.setJavaScriptCanOpenWindowsAutomatically(true);
        if (Build.VERSION.SDK_INT >= 21) {
            settings.setMixedContentMode(0);
        }
        com.google.android.gms.ads.internal.zzo.zzbv().zza(zzaVar, versionInfoParcel.zzGG, settings);
        com.google.android.gms.ads.internal.zzo.zzbx().zza(getContext(), settings);
        setDownloadListener(this);
        this.zzBd = com.google.android.gms.ads.internal.zzo.zzbx().zzb(this, z2);
        setWebViewClient(this.zzBd);
        setWebChromeClient(com.google.android.gms.ads.internal.zzo.zzbx().zzf(this));
        zzgX();
        if (zzlk.zzoW()) {
            addJavascriptInterface(new zzih(this), "googleAdsJsInterface");
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static zzig zzb(Context context, AdSizeParcel adSizeParcel, boolean z, boolean z2, zzan zzanVar, VersionInfoParcel versionInfoParcel) {
        return new zzig(new zza(context), adSizeParcel, z, z2, zzanVar, versionInfoParcel);
    }

    private void zzgU() {
        synchronized (this.zzqt) {
            this.zzFO = com.google.android.gms.ads.internal.zzo.zzby().zzgc();
            if (this.zzFO == null) {
                try {
                    evaluateJavascript("(function(){})()", null);
                    zzb((Boolean) true);
                } catch (IllegalStateException e) {
                    zzb((Boolean) false);
                }
            }
        }
    }

    private void zzgV() {
        Activity zzgB = zzgB();
        if (!this.zzHu || zzgB == null) {
            return;
        }
        com.google.android.gms.ads.internal.zzo.zzbx().zzb(zzgB, this);
        this.zzHu = false;
    }

    private void zzgX() {
        synchronized (this.zzqt) {
            if (this.zzHs || this.zzxT.zzsn) {
                if (Build.VERSION.SDK_INT < 14) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzay("Disabling hardware acceleration on an overlay.");
                    zzgY();
                } else {
                    com.google.android.gms.ads.internal.util.client.zzb.zzay("Enabling hardware acceleration on an overlay.");
                    zzgZ();
                }
            } else if (Build.VERSION.SDK_INT < 18) {
                com.google.android.gms.ads.internal.util.client.zzb.zzay("Disabling hardware acceleration on an AdView.");
                zzgY();
            } else {
                com.google.android.gms.ads.internal.util.client.zzb.zzay("Enabling hardware acceleration on an AdView.");
                zzgZ();
            }
        }
    }

    private void zzgY() {
        synchronized (this.zzqt) {
            if (!this.zzHt) {
                com.google.android.gms.ads.internal.zzo.zzbx().zzm(this);
            }
            this.zzHt = true;
        }
    }

    private void zzgZ() {
        synchronized (this.zzqt) {
            if (this.zzHt) {
                com.google.android.gms.ads.internal.zzo.zzbx().zzl(this);
            }
            this.zzHt = false;
        }
    }

    @Override // android.webkit.WebView, com.google.android.gms.internal.zzid
    public void destroy() {
        synchronized (this.zzqt) {
            zzgV();
            if (this.zzHp != null) {
                this.zzHp.close();
                this.zzHp.onDestroy();
                this.zzHp = null;
            }
            this.zzBd.reset();
            if (this.zzHr) {
                return;
            }
            com.google.android.gms.ads.internal.zzo.zzbH().zza(this);
            this.zzHr = true;
            com.google.android.gms.ads.internal.util.client.zzb.zzaB("Initiating WebView self destruct sequence in 3...");
            this.zzBd.zzgN();
        }
    }

    @Override // android.webkit.WebView
    public void evaluateJavascript(String script, ValueCallback<String> resultCallback) {
        synchronized (this.zzqt) {
            if (!isDestroyed()) {
                super.evaluateJavascript(script, resultCallback);
                return;
            }
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("The webview is destroyed. Ignoring action.");
            if (resultCallback != null) {
                resultCallback.onReceiveValue(null);
            }
        }
    }

    @Override // com.google.android.gms.internal.zzid
    public int getRequestedOrientation() {
        int i;
        synchronized (this.zzqt) {
            i = this.zzHv;
        }
        return i;
    }

    @Override // com.google.android.gms.internal.zzid
    public WebView getWebView() {
        return this;
    }

    @Override // com.google.android.gms.internal.zzid
    public boolean isDestroyed() {
        boolean z;
        synchronized (this.zzqt) {
            z = this.zzHr;
        }
        return z;
    }

    @Override // android.webkit.WebView, com.google.android.gms.internal.zzid
    public void loadData(String data, String mimeType, String encoding) {
        synchronized (this.zzqt) {
            if (isDestroyed()) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("The webview is destroyed. Ignoring action.");
            } else {
                super.loadData(data, mimeType, encoding);
            }
        }
    }

    @Override // android.webkit.WebView, com.google.android.gms.internal.zzid
    public void loadDataWithBaseURL(String baseUrl, String data, String mimeType, String encoding, String historyUrl) {
        synchronized (this.zzqt) {
            if (isDestroyed()) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("The webview is destroyed. Ignoring action.");
            } else {
                super.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
            }
        }
    }

    @Override // android.webkit.WebView, com.google.android.gms.internal.zzid
    public void loadUrl(String uri) {
        synchronized (this.zzqt) {
            if (isDestroyed()) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("The webview is destroyed. Ignoring action.");
            } else {
                super.loadUrl(uri);
            }
        }
    }

    @Override // android.webkit.WebView, android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        synchronized (this.zzqt) {
            super.onAttachedToWindow();
            if (!isDestroyed()) {
                this.zzHx = true;
                if (this.zzBd.zzbU()) {
                    zzgW();
                }
            }
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        synchronized (this.zzqt) {
            if (!isDestroyed()) {
                zzgV();
                this.zzHx = false;
            }
            super.onDetachedFromWindow();
        }
    }

    @Override // android.webkit.DownloadListener
    public void onDownloadStart(String url, String userAgent, String contentDisposition, String mimeType, long size) {
        try {
            Intent intent = new Intent("android.intent.action.VIEW");
            intent.setDataAndType(Uri.parse(url), mimeType);
            getContext().startActivity(intent);
        } catch (ActivityNotFoundException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzay("Couldn't find an Activity to view url/mimetype: " + url + " / " + mimeType);
        }
    }

    @Override // android.webkit.WebView, android.view.View
    protected void onDraw(Canvas canvas) {
        if (isDestroyed()) {
            return;
        }
        if (Build.VERSION.SDK_INT == 21 && canvas.isHardwareAccelerated() && !isAttachedToWindow()) {
            return;
        }
        super.onDraw(canvas);
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public void onGlobalLayout() {
        boolean zzgT = zzgT();
        com.google.android.gms.ads.internal.overlay.zzc zzgD = zzgD();
        if (zzgD == null || !zzgT) {
            return;
        }
        zzgD.zzev();
    }

    @Override // android.webkit.WebView, android.widget.AbsoluteLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int i = ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        synchronized (this.zzqt) {
            if (isDestroyed()) {
                setMeasuredDimension(0, 0);
            } else if (isInEditMode() || this.zzHs) {
                super.onMeasure(widthMeasureSpec, heightMeasureSpec);
            } else if (this.zzxT.zzsn) {
                DisplayMetrics displayMetrics = new DisplayMetrics();
                this.zzqF.getDefaultDisplay().getMetrics(displayMetrics);
                setMeasuredDimension(displayMetrics.widthPixels, displayMetrics.heightPixels);
            } else {
                int mode = View.MeasureSpec.getMode(widthMeasureSpec);
                int size = View.MeasureSpec.getSize(widthMeasureSpec);
                int mode2 = View.MeasureSpec.getMode(heightMeasureSpec);
                int size2 = View.MeasureSpec.getSize(heightMeasureSpec);
                int i2 = (mode == Integer.MIN_VALUE || mode == 1073741824) ? size : Integer.MAX_VALUE;
                if (mode2 == Integer.MIN_VALUE || mode2 == 1073741824) {
                    i = size2;
                }
                if (this.zzxT.widthPixels > i2 || this.zzxT.heightPixels > i) {
                    float f = this.zzHo.getResources().getDisplayMetrics().density;
                    com.google.android.gms.ads.internal.util.client.zzb.zzaC("Not enough space to show ad. Needs " + ((int) (this.zzxT.widthPixels / f)) + "x" + ((int) (this.zzxT.heightPixels / f)) + " dp, but only has " + ((int) (size / f)) + "x" + ((int) (size2 / f)) + " dp.");
                    if (getVisibility() != 8) {
                        setVisibility(4);
                    }
                    setMeasuredDimension(0, 0);
                } else {
                    if (getVisibility() != 8) {
                        setVisibility(0);
                    }
                    setMeasuredDimension(this.zzxT.widthPixels, this.zzxT.heightPixels);
                }
            }
        }
    }

    @Override // android.webkit.WebView
    public void onPause() {
        if (isDestroyed()) {
            return;
        }
        try {
            super.onPause();
        } catch (Exception e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzb("Could not pause webview.", e);
        }
    }

    @Override // android.webkit.WebView
    public void onResume() {
        if (isDestroyed()) {
            return;
        }
        try {
            super.onResume();
        } catch (Exception e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzb("Could not resume webview.", e);
        }
    }

    @Override // android.webkit.WebView, android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        if (this.zzvA != null) {
            this.zzvA.zza(event);
        }
        if (isDestroyed()) {
            return false;
        }
        return super.onTouchEvent(event);
    }

    @Override // com.google.android.gms.internal.zzid
    public void setContext(Context context) {
        this.zzHo.setBaseContext(context);
    }

    @Override // com.google.android.gms.internal.zzid
    public void setRequestedOrientation(int requestedOrientation) {
        synchronized (this.zzqt) {
            this.zzHv = requestedOrientation;
            if (this.zzHp != null) {
                this.zzHp.setRequestedOrientation(this.zzHv);
            }
        }
    }

    @Override // android.webkit.WebView, com.google.android.gms.internal.zzid
    public void stopLoading() {
        if (isDestroyed()) {
            return;
        }
        try {
            super.stopLoading();
        } catch (Exception e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzb("Could not stop loading webview.", e);
        }
    }

    @Override // com.google.android.gms.internal.zzid
    public void zzB(boolean z) {
        synchronized (this.zzqt) {
            this.zzHs = z;
            zzgX();
        }
    }

    @Override // com.google.android.gms.internal.zzid
    public void zzC(boolean z) {
        synchronized (this.zzqt) {
            if (this.zzHp != null) {
                this.zzHp.zza(this.zzBd.zzbU(), z);
            } else {
                this.zzHq = z;
            }
        }
    }

    @Override // com.google.android.gms.internal.zzid
    public void zza(Context context, AdSizeParcel adSizeParcel) {
        synchronized (this.zzqt) {
            zzgV();
            setContext(context);
            this.zzHp = null;
            this.zzxT = adSizeParcel;
            this.zzHs = false;
            this.zzHq = false;
            this.zzHv = -1;
            com.google.android.gms.ads.internal.zzo.zzbx().zzb(this);
            loadUrl("about:blank");
            this.zzBd.reset();
            setOnTouchListener(null);
            setOnClickListener(null);
        }
    }

    @Override // com.google.android.gms.internal.zzid
    public void zza(AdSizeParcel adSizeParcel) {
        synchronized (this.zzqt) {
            this.zzxT = adSizeParcel;
            requestLayout();
        }
    }

    @Override // com.google.android.gms.internal.zzid
    public void zza(com.google.android.gms.ads.internal.overlay.zzc zzcVar) {
        synchronized (this.zzqt) {
            this.zzHp = zzcVar;
        }
    }

    protected void zza(String str, ValueCallback<String> valueCallback) {
        synchronized (this.zzqt) {
            if (isDestroyed()) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("The webview is destroyed. Ignoring action.");
                if (valueCallback != null) {
                    valueCallback.onReceiveValue(null);
                }
            } else {
                evaluateJavascript(str, valueCallback);
            }
        }
    }

    @Override // com.google.android.gms.internal.zzid
    public void zza(String str, String str2) {
        zzaF(str + "(" + str2 + ");");
    }

    @Override // com.google.android.gms.internal.zzid
    public void zza(String str, JSONObject jSONObject) {
        if (jSONObject == null) {
            jSONObject = new JSONObject();
        }
        zza(str, jSONObject.toString());
    }

    @Override // com.google.android.gms.internal.zzid
    public void zzaD(String str) {
        synchronized (this.zzqt) {
            super.loadUrl(str);
        }
    }

    protected void zzaE(String str) {
        synchronized (this.zzqt) {
            if (isDestroyed()) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("The webview is destroyed. Ignoring action.");
            } else {
                loadUrl(str);
            }
        }
    }

    protected void zzaF(String str) {
        if (!zzlk.zzoX()) {
            zzaE("javascript:" + str);
            return;
        }
        if (zzgc() == null) {
            zzgU();
        }
        if (zzgc().booleanValue()) {
            zza(str, (ValueCallback<String>) null);
        } else {
            zzaE("javascript:" + str);
        }
    }

    @Override // com.google.android.gms.internal.zzid
    public AdSizeParcel zzaN() {
        AdSizeParcel adSizeParcel;
        synchronized (this.zzqt) {
            adSizeParcel = this.zzxT;
        }
        return adSizeParcel;
    }

    @Override // com.google.android.gms.internal.zzid
    public void zzb(com.google.android.gms.ads.internal.overlay.zzc zzcVar) {
        synchronized (this.zzqt) {
            this.zzHw = zzcVar;
        }
    }

    void zzb(Boolean bool) {
        this.zzFO = bool;
        com.google.android.gms.ads.internal.zzo.zzby().zzb(bool);
    }

    @Override // com.google.android.gms.internal.zzid
    public void zzb(String str, JSONObject jSONObject) {
        if (jSONObject == null) {
            jSONObject = new JSONObject();
        }
        String jSONObject2 = jSONObject.toString();
        StringBuilder sb = new StringBuilder();
        sb.append("AFMA_ReceiveMessage('");
        sb.append(str);
        sb.append("'");
        sb.append(",");
        sb.append(jSONObject2);
        sb.append(");");
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("Dispatching AFMA event: " + sb.toString());
        zzaF(sb.toString());
    }

    @Override // com.google.android.gms.internal.zzid
    public void zzc(String str, Map<String, ?> map) {
        try {
            zzb(str, com.google.android.gms.ads.internal.zzo.zzbv().zzy(map));
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Could not convert parameters to JSON.");
        }
    }

    @Override // com.google.android.gms.internal.zzid
    public void zzew() {
        HashMap hashMap = new HashMap(1);
        hashMap.put("version", this.zzoM.zzGG);
        zzc("onshow", hashMap);
    }

    @Override // com.google.android.gms.internal.zzid
    public void zzgA() {
        HashMap hashMap = new HashMap(1);
        hashMap.put("version", this.zzoM.zzGG);
        zzc("onhide", hashMap);
    }

    @Override // com.google.android.gms.internal.zzid
    public Activity zzgB() {
        return this.zzHo.zzgB();
    }

    @Override // com.google.android.gms.internal.zzid
    public Context zzgC() {
        return this.zzHo.zzgC();
    }

    @Override // com.google.android.gms.internal.zzid
    public com.google.android.gms.ads.internal.overlay.zzc zzgD() {
        com.google.android.gms.ads.internal.overlay.zzc zzcVar;
        synchronized (this.zzqt) {
            zzcVar = this.zzHp;
        }
        return zzcVar;
    }

    @Override // com.google.android.gms.internal.zzid
    public com.google.android.gms.ads.internal.overlay.zzc zzgE() {
        com.google.android.gms.ads.internal.overlay.zzc zzcVar;
        synchronized (this.zzqt) {
            zzcVar = this.zzHw;
        }
        return zzcVar;
    }

    @Override // com.google.android.gms.internal.zzid
    public zzie zzgF() {
        return this.zzBd;
    }

    @Override // com.google.android.gms.internal.zzid
    public boolean zzgG() {
        return this.zzHq;
    }

    @Override // com.google.android.gms.internal.zzid
    public zzan zzgH() {
        return this.zzvA;
    }

    @Override // com.google.android.gms.internal.zzid
    public VersionInfoParcel zzgI() {
        return this.zzoM;
    }

    @Override // com.google.android.gms.internal.zzid
    public boolean zzgJ() {
        boolean z;
        synchronized (this.zzqt) {
            z = this.zzHs;
        }
        return z;
    }

    @Override // com.google.android.gms.internal.zzid
    public void zzgK() {
        synchronized (this.zzqt) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaB("Destroying WebView!");
            super.destroy();
        }
    }

    @Override // com.google.android.gms.internal.zzid
    public void zzgL() {
        synchronized (this.zzqt) {
            zzgW();
        }
    }

    public boolean zzgT() {
        int i;
        int i2;
        if (zzgF().zzbU()) {
            DisplayMetrics zza2 = com.google.android.gms.ads.internal.zzo.zzbv().zza(this.zzqF);
            int zzb = com.google.android.gms.ads.internal.client.zzk.zzcA().zzb(zza2, zza2.widthPixels);
            int zzb2 = com.google.android.gms.ads.internal.client.zzk.zzcA().zzb(zza2, zza2.heightPixels);
            Activity zzgB = zzgB();
            if (zzgB == null || zzgB.getWindow() == null) {
                i = zzb2;
                i2 = zzb;
            } else {
                int[] zzg = com.google.android.gms.ads.internal.zzo.zzbv().zzg(zzgB);
                i2 = com.google.android.gms.ads.internal.client.zzk.zzcA().zzb(zza2, zzg[0]);
                i = com.google.android.gms.ads.internal.client.zzk.zzcA().zzb(zza2, zzg[1]);
            }
            if (this.zzyW == zzb && this.zzyX == zzb2 && this.zzyZ == i2 && this.zzza == i) {
                return false;
            }
            boolean z = (this.zzyW == zzb && this.zzyX == zzb2) ? false : true;
            this.zzyW = zzb;
            this.zzyX = zzb2;
            this.zzyZ = i2;
            this.zzza = i;
            new zzeu(this).zza(zzb, zzb2, i2, i, zza2.density, this.zzqF.getDefaultDisplay().getRotation());
            return z;
        }
        return false;
    }

    void zzgW() {
        Activity zzgB = zzgB();
        if (this.zzHu || zzgB == null || !this.zzHx) {
            return;
        }
        com.google.android.gms.ads.internal.zzo.zzbv().zza(zzgB, this);
        this.zzHu = true;
    }

    Boolean zzgc() {
        Boolean bool;
        synchronized (this.zzqt) {
            bool = this.zzFO;
        }
        return bool;
    }

    @Override // com.google.android.gms.internal.zzid
    public void zzv(int i) {
        HashMap hashMap = new HashMap(2);
        hashMap.put("closetype", String.valueOf(i));
        hashMap.put("version", this.zzoM.zzGG);
        zzc("onhide", hashMap);
    }
}
