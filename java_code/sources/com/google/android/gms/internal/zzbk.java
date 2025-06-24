package com.google.android.gms.internal;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.Context;
import android.os.PowerManager;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.ValueCallback;
import android.webkit.WebView;
import android.widget.EditText;
import android.widget.TextView;
import org.json.JSONException;
import org.json.JSONObject;
@zzgd
/* loaded from: classes.dex */
public class zzbk extends Thread {
    private final zzbj zzrw;
    private final zzbi zzrx;
    private final zzgc zzry;
    private boolean mStarted = false;
    private boolean zzrv = false;
    private boolean zzam = false;
    private final Object zzqt = new Object();
    private final int zzrj = zzbz.zzud.get().intValue();
    private final int zzrA = zzbz.zzue.get().intValue();
    private final int zzrl = zzbz.zzuf.get().intValue();
    private final int zzrB = zzbz.zzug.get().intValue();
    private final int zzrz = zzbz.zzuh.get().intValue();

    /* JADX INFO: Access modifiers changed from: package-private */
    @zzgd
    /* loaded from: classes.dex */
    public class zza {
        final int zzrI;
        final int zzrJ;

        zza(int i, int i2) {
            this.zzrI = i;
            this.zzrJ = i2;
        }
    }

    public zzbk(zzbj zzbjVar, zzbi zzbiVar, zzgc zzgcVar) {
        this.zzrw = zzbjVar;
        this.zzrx = zzbiVar;
        this.zzry = zzgcVar;
        setName("ContentFetchTask");
    }

    @Override // java.lang.Thread, java.lang.Runnable
    public void run() {
        while (!this.zzam) {
            try {
            } catch (Throwable th) {
                com.google.android.gms.ads.internal.util.client.zzb.zzb("Error in ContentFetchTask", th);
                this.zzry.zza(th, true);
            }
            if (zzcq()) {
                Activity activity = this.zzrw.getActivity();
                if (activity == null) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzay("ContentFetchThread: no activity");
                } else {
                    zza(activity);
                }
            } else {
                com.google.android.gms.ads.internal.util.client.zzb.zzay("ContentFetchTask: sleeping");
                zzcs();
            }
            Thread.sleep(this.zzrz * 1000);
            synchronized (this.zzqt) {
                while (this.zzrv) {
                    try {
                        com.google.android.gms.ads.internal.util.client.zzb.zzay("ContentFetchTask: waiting");
                        this.zzqt.wait();
                    } catch (InterruptedException e) {
                    }
                }
            }
        }
    }

    public void wakeup() {
        synchronized (this.zzqt) {
            this.zzrv = false;
            this.zzqt.notifyAll();
            com.google.android.gms.ads.internal.util.client.zzb.zzay("ContentFetchThread: wakeup");
        }
    }

    zza zza(View view, zzbh zzbhVar) {
        if (view == null) {
            return new zza(0, 0);
        }
        if ((view instanceof TextView) && !(view instanceof EditText)) {
            CharSequence text = ((TextView) view).getText();
            if (TextUtils.isEmpty(text)) {
                return new zza(0, 0);
            }
            zzbhVar.zzv(text.toString());
            return new zza(1, 0);
        } else if ((view instanceof WebView) && !(view instanceof zzid)) {
            zzbhVar.zzcl();
            return zza((WebView) view, zzbhVar) ? new zza(0, 1) : new zza(0, 0);
        } else if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            int i = 0;
            int i2 = 0;
            for (int i3 = 0; i3 < viewGroup.getChildCount(); i3++) {
                zza zza2 = zza(viewGroup.getChildAt(i3), zzbhVar);
                i2 += zza2.zzrI;
                i += zza2.zzrJ;
            }
            return new zza(i2, i);
        } else {
            return new zza(0, 0);
        }
    }

    void zza(Activity activity) {
        if (activity == null) {
            return;
        }
        View view = null;
        if (activity.getWindow() != null && activity.getWindow().getDecorView() != null) {
            view = activity.getWindow().getDecorView().findViewById(16908290);
        }
        if (view != null) {
            zzf(view);
        }
    }

    void zza(zzbh zzbhVar, WebView webView, String str) {
        zzbhVar.zzck();
        try {
            if (!TextUtils.isEmpty(str)) {
                String optString = new JSONObject(str).optString("text");
                if (TextUtils.isEmpty(webView.getTitle())) {
                    zzbhVar.zzu(optString);
                } else {
                    zzbhVar.zzu(webView.getTitle() + "\n" + optString);
                }
            }
            if (zzbhVar.zzch()) {
                this.zzrx.zzb(zzbhVar);
            }
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzay("Json string may be malformed.");
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zza("Failed to get webview content.", th);
            this.zzry.zza(th, true);
        }
    }

    boolean zza(ActivityManager.RunningAppProcessInfo runningAppProcessInfo) {
        return runningAppProcessInfo.importance == 100;
    }

    boolean zza(final WebView webView, final zzbh zzbhVar) {
        if (zzlk.zzoX()) {
            zzbhVar.zzcl();
            webView.post(new Runnable() { // from class: com.google.android.gms.internal.zzbk.2
                ValueCallback<String> zzrE = new ValueCallback<String>() { // from class: com.google.android.gms.internal.zzbk.2.1
                    @Override // android.webkit.ValueCallback
                    /* renamed from: zzx */
                    public void onReceiveValue(String str) {
                        zzbk.this.zza(zzbhVar, webView, str);
                    }
                };

                @Override // java.lang.Runnable
                public void run() {
                    if (webView.getSettings().getJavaScriptEnabled()) {
                        try {
                            webView.evaluateJavascript("(function() { return  {text:document.body.innerText}})();", this.zzrE);
                        } catch (Throwable th) {
                            this.zzrE.onReceiveValue("");
                        }
                    }
                }
            });
            return true;
        }
        return false;
    }

    public void zzcp() {
        synchronized (this.zzqt) {
            if (this.mStarted) {
                com.google.android.gms.ads.internal.util.client.zzb.zzay("Content hash thread already started, quiting...");
                return;
            }
            this.mStarted = true;
            start();
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:20:0x0045, code lost:
        if (zza(r0) == false) goto L29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x004b, code lost:
        if (r1.inKeyguardRestrictedInputMode() != false) goto L29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x0051, code lost:
        if (zzr(r3) == false) goto L29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x0053, code lost:
        return true;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    boolean zzcq() {
        /*
            r7 = this;
            r2 = 0
            com.google.android.gms.internal.zzbj r0 = r7.zzrw     // Catch: java.lang.Throwable -> L57
            android.content.Context r3 = r0.getContext()     // Catch: java.lang.Throwable -> L57
            if (r3 != 0) goto Lb
            r0 = r2
        La:
            return r0
        Lb:
            java.lang.String r0 = "activity"
            java.lang.Object r0 = r3.getSystemService(r0)     // Catch: java.lang.Throwable -> L57
            android.app.ActivityManager r0 = (android.app.ActivityManager) r0     // Catch: java.lang.Throwable -> L57
            java.lang.String r1 = "keyguard"
            java.lang.Object r1 = r3.getSystemService(r1)     // Catch: java.lang.Throwable -> L57
            android.app.KeyguardManager r1 = (android.app.KeyguardManager) r1     // Catch: java.lang.Throwable -> L57
            if (r0 == 0) goto L1f
            if (r1 != 0) goto L21
        L1f:
            r0 = r2
            goto La
        L21:
            java.util.List r0 = r0.getRunningAppProcesses()     // Catch: java.lang.Throwable -> L57
            if (r0 != 0) goto L29
            r0 = r2
            goto La
        L29:
            java.util.Iterator r4 = r0.iterator()     // Catch: java.lang.Throwable -> L57
        L2d:
            boolean r0 = r4.hasNext()     // Catch: java.lang.Throwable -> L57
            if (r0 == 0) goto L55
            java.lang.Object r0 = r4.next()     // Catch: java.lang.Throwable -> L57
            android.app.ActivityManager$RunningAppProcessInfo r0 = (android.app.ActivityManager.RunningAppProcessInfo) r0     // Catch: java.lang.Throwable -> L57
            int r5 = android.os.Process.myPid()     // Catch: java.lang.Throwable -> L57
            int r6 = r0.pid     // Catch: java.lang.Throwable -> L57
            if (r5 != r6) goto L2d
            boolean r0 = r7.zza(r0)     // Catch: java.lang.Throwable -> L57
            if (r0 == 0) goto L55
            boolean r0 = r1.inKeyguardRestrictedInputMode()     // Catch: java.lang.Throwable -> L57
            if (r0 != 0) goto L55
            boolean r0 = r7.zzr(r3)     // Catch: java.lang.Throwable -> L57
            if (r0 == 0) goto L55
            r0 = 1
            goto La
        L55:
            r0 = r2
            goto La
        L57:
            r0 = move-exception
            r0 = r2
            goto La
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.zzbk.zzcq():boolean");
    }

    public zzbh zzcr() {
        return this.zzrx.zzco();
    }

    public void zzcs() {
        synchronized (this.zzqt) {
            this.zzrv = true;
            com.google.android.gms.ads.internal.util.client.zzb.zzay("ContentFetchThread: paused, mPause = " + this.zzrv);
        }
    }

    public boolean zzct() {
        return this.zzrv;
    }

    boolean zzf(final View view) {
        if (view == null) {
            return false;
        }
        view.post(new Runnable() { // from class: com.google.android.gms.internal.zzbk.1
            @Override // java.lang.Runnable
            public void run() {
                zzbk.this.zzg(view);
            }
        });
        return true;
    }

    void zzg(View view) {
        try {
            zzbh zzbhVar = new zzbh(this.zzrj, this.zzrA, this.zzrl, this.zzrB);
            zza zza2 = zza(view, zzbhVar);
            zzbhVar.zzcm();
            if (zza2.zzrI == 0 && zza2.zzrJ == 0) {
                return;
            }
            if (zza2.zzrJ == 0 && zzbhVar.zzcn() == 0) {
                return;
            }
            if (zza2.zzrJ == 0 && this.zzrx.zza(zzbhVar)) {
                return;
            }
            this.zzrx.zzc(zzbhVar);
        } catch (Exception e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzb("Exception in fetchContentOnUIThread", e);
            this.zzry.zza(e, true);
        }
    }

    boolean zzr(Context context) {
        PowerManager powerManager = (PowerManager) context.getSystemService("power");
        if (powerManager == null) {
            return false;
        }
        return powerManager.isScreenOn();
    }
}
