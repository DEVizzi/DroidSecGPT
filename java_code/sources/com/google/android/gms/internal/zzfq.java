package com.google.android.gms.internal;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.os.AsyncTask;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.view.View;
import android.webkit.WebView;
import com.google.android.gms.ads.internal.request.AdResponseParcel;
import com.google.android.gms.internal.zzie;
@zzgd
/* loaded from: classes.dex */
public class zzfq implements Runnable {
    private final Handler zzBf;
    private final long zzBg;
    private long zzBh;
    private zzie.zza zzBi;
    protected boolean zzBj;
    protected boolean zzBk;
    private final int zznM;
    private final int zznN;
    protected final zzid zzoA;

    /* loaded from: classes.dex */
    protected final class zza extends AsyncTask<Void, Void, Boolean> {
        private final WebView zzBl;
        private Bitmap zzBm;

        public zza(WebView webView) {
            this.zzBl = webView;
        }

        @Override // android.os.AsyncTask
        protected synchronized void onPreExecute() {
            this.zzBm = Bitmap.createBitmap(zzfq.this.zznM, zzfq.this.zznN, Bitmap.Config.ARGB_8888);
            this.zzBl.setVisibility(0);
            this.zzBl.measure(View.MeasureSpec.makeMeasureSpec(zzfq.this.zznM, 0), View.MeasureSpec.makeMeasureSpec(zzfq.this.zznN, 0));
            this.zzBl.layout(0, 0, zzfq.this.zznM, zzfq.this.zznN);
            this.zzBl.draw(new Canvas(this.zzBm));
            this.zzBl.invalidate();
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* renamed from: zza */
        public synchronized Boolean doInBackground(Void... voidArr) {
            boolean z;
            int width = this.zzBm.getWidth();
            int height = this.zzBm.getHeight();
            if (width == 0 || height == 0) {
                z = false;
            } else {
                int i = 0;
                for (int i2 = 0; i2 < width; i2 += 10) {
                    for (int i3 = 0; i3 < height; i3 += 10) {
                        if (this.zzBm.getPixel(i2, i3) != 0) {
                            i++;
                        }
                    }
                }
                z = Boolean.valueOf(((double) i) / (((double) (width * height)) / 100.0d) > 0.1d);
            }
            return z;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* renamed from: zza */
        public void onPostExecute(Boolean bool) {
            zzfq.zzc(zzfq.this);
            if (bool.booleanValue() || zzfq.this.zzfl() || zzfq.this.zzBh <= 0) {
                zzfq.this.zzBk = bool.booleanValue();
                zzfq.this.zzBi.zza(zzfq.this.zzoA, true);
            } else if (zzfq.this.zzBh > 0) {
                if (com.google.android.gms.ads.internal.util.client.zzb.zzL(2)) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzay("Ad not detected, scheduling another run.");
                }
                zzfq.this.zzBf.postDelayed(zzfq.this, zzfq.this.zzBg);
            }
        }
    }

    public zzfq(zzie.zza zzaVar, zzid zzidVar, int i, int i2) {
        this(zzaVar, zzidVar, i, i2, 200L, 50L);
    }

    public zzfq(zzie.zza zzaVar, zzid zzidVar, int i, int i2, long j, long j2) {
        this.zzBg = j;
        this.zzBh = j2;
        this.zzBf = new Handler(Looper.getMainLooper());
        this.zzoA = zzidVar;
        this.zzBi = zzaVar;
        this.zzBj = false;
        this.zzBk = false;
        this.zznN = i2;
        this.zznM = i;
    }

    static /* synthetic */ long zzc(zzfq zzfqVar) {
        long j = zzfqVar.zzBh - 1;
        zzfqVar.zzBh = j;
        return j;
    }

    @Override // java.lang.Runnable
    public void run() {
        if (this.zzoA == null || zzfl()) {
            this.zzBi.zza(this.zzoA, true);
        } else {
            new zza(this.zzoA.getWebView()).execute(new Void[0]);
        }
    }

    public void zza(AdResponseParcel adResponseParcel) {
        zza(adResponseParcel, new zzil(this, this.zzoA, adResponseParcel.zzCR));
    }

    public void zza(AdResponseParcel adResponseParcel, zzil zzilVar) {
        this.zzoA.setWebViewClient(zzilVar);
        this.zzoA.loadDataWithBaseURL(TextUtils.isEmpty(adResponseParcel.zzzG) ? null : com.google.android.gms.ads.internal.zzo.zzbv().zzat(adResponseParcel.zzzG), adResponseParcel.zzCI, "text/html", "UTF-8", null);
    }

    public void zzfj() {
        this.zzBf.postDelayed(this, this.zzBg);
    }

    public synchronized void zzfk() {
        this.zzBj = true;
    }

    public synchronized boolean zzfl() {
        return this.zzBj;
    }

    public boolean zzfm() {
        return this.zzBk;
    }
}
