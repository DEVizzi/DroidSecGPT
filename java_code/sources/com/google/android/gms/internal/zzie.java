package com.google.android.gms.internal;

import android.net.Uri;
import android.support.v4.media.TransportMediator;
import android.view.KeyEvent;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import com.google.android.gms.ads.internal.overlay.AdLauncherIntentInfoParcel;
import com.google.android.gms.ads.internal.overlay.AdOverlayInfoParcel;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
@zzgd
/* loaded from: classes.dex */
public class zzie extends WebViewClient {
    private zza zzBi;
    private final HashMap<String, List<zzdg>> zzHb;
    private com.google.android.gms.ads.internal.overlay.zzf zzHc;
    private boolean zzHd;
    private com.google.android.gms.ads.internal.overlay.zzk zzHe;
    private final zzet zzHf;
    private boolean zzHg;
    private boolean zzHh;
    private boolean zzHi;
    private boolean zzHj;
    private int zzHk;
    protected final zzid zzoA;
    private boolean zzqs;
    private final Object zzqt;
    private com.google.android.gms.ads.internal.client.zza zzrU;
    private zzde zzvU;
    private zzdk zzwu;
    private com.google.android.gms.ads.internal.zzd zzww;
    private zzep zzwx;
    private zzdi zzwz;
    private zzev zzyE;

    /* loaded from: classes.dex */
    public interface zza {
        void zza(zzid zzidVar, boolean z);
    }

    /* loaded from: classes.dex */
    private static class zzb implements com.google.android.gms.ads.internal.overlay.zzf {
        private com.google.android.gms.ads.internal.overlay.zzf zzHc;
        private zzid zzHn;

        public zzb(zzid zzidVar, com.google.android.gms.ads.internal.overlay.zzf zzfVar) {
            this.zzHn = zzidVar;
            this.zzHc = zzfVar;
        }

        @Override // com.google.android.gms.ads.internal.overlay.zzf
        public void zzaV() {
            this.zzHc.zzaV();
            this.zzHn.zzgA();
        }

        @Override // com.google.android.gms.ads.internal.overlay.zzf
        public void zzaW() {
            this.zzHc.zzaW();
            this.zzHn.zzew();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class zzc implements zzdg {
        private zzc() {
        }

        @Override // com.google.android.gms.internal.zzdg
        public void zza(zzid zzidVar, Map<String, String> map) {
            if (map.keySet().contains("start")) {
                zzie.this.zzgO();
            } else if (map.keySet().contains("stop")) {
                zzie.this.zzgP();
            } else if (map.keySet().contains("cancel")) {
                zzie.this.zzgQ();
            }
        }
    }

    public zzie(zzid zzidVar, boolean z) {
        this(zzidVar, z, new zzet(zzidVar, zzidVar.zzgC(), new zzbq(zzidVar.getContext())), null);
    }

    zzie(zzid zzidVar, boolean z, zzet zzetVar, zzep zzepVar) {
        this.zzHb = new HashMap<>();
        this.zzqt = new Object();
        this.zzHd = false;
        this.zzoA = zzidVar;
        this.zzqs = z;
        this.zzHf = zzetVar;
        this.zzwx = zzepVar;
    }

    private static boolean zzf(Uri uri) {
        String scheme = uri.getScheme();
        return "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zzgO() {
        this.zzHk++;
        zzgR();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zzgP() {
        this.zzHk--;
        zzgR();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zzgQ() {
        this.zzHj = true;
        zzgR();
    }

    @Override // android.webkit.WebViewClient
    public final void onLoadResource(WebView webView, String url) {
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("Loading resource: " + url);
        Uri parse = Uri.parse(url);
        if ("gmsg".equalsIgnoreCase(parse.getScheme()) && "mobileads.google.com".equalsIgnoreCase(parse.getHost())) {
            zzg(parse);
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onPageFinished(WebView webView, String url) {
        synchronized (this.zzqt) {
            if (this.zzHh && "about:blank".equals(url)) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaB("Blank page loaded, 1...");
                this.zzoA.zzgK();
                return;
            }
            this.zzHi = true;
            zzgR();
        }
    }

    public final void reset() {
        synchronized (this.zzqt) {
            this.zzHb.clear();
            this.zzrU = null;
            this.zzHc = null;
            this.zzBi = null;
            this.zzvU = null;
            this.zzHd = false;
            this.zzqs = false;
            this.zzwz = null;
            this.zzHe = null;
            if (this.zzwx != null) {
                this.zzwx.zzn(true);
                this.zzwx = null;
            }
            this.zzHg = false;
        }
    }

    @Override // android.webkit.WebViewClient
    public boolean shouldOverrideKeyEvent(WebView view, KeyEvent event) {
        switch (event.getKeyCode()) {
            case 79:
            case 85:
            case 86:
            case 87:
            case 88:
            case 89:
            case 90:
            case 91:
            case TransportMediator.KEYCODE_MEDIA_PLAY /* 126 */:
            case TransportMediator.KEYCODE_MEDIA_PAUSE /* 127 */:
            case 128:
            case 129:
            case TransportMediator.KEYCODE_MEDIA_RECORD /* 130 */:
            case 222:
                return true;
            default:
                return false;
        }
    }

    @Override // android.webkit.WebViewClient
    public final boolean shouldOverrideUrlLoading(WebView webView, String url) {
        Uri uri;
        com.google.android.gms.ads.internal.util.client.zzb.zzaB("AdWebView shouldOverrideUrlLoading: " + url);
        Uri parse = Uri.parse(url);
        if ("gmsg".equalsIgnoreCase(parse.getScheme()) && "mobileads.google.com".equalsIgnoreCase(parse.getHost())) {
            zzg(parse);
        } else if (this.zzHd && webView == this.zzoA && zzf(parse)) {
            if (!this.zzHg) {
                this.zzHg = true;
                if (this.zzrU != null && zzbz.zzul.get().booleanValue()) {
                    this.zzrU.onAdClicked();
                }
            }
            return super.shouldOverrideUrlLoading(webView, url);
        } else if (this.zzoA.willNotDraw()) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("AdWebView unable to handle URL: " + url);
        } else {
            try {
                zzan zzgH = this.zzoA.zzgH();
                if (zzgH != null && zzgH.zzb(parse)) {
                    parse = zzgH.zza(parse, this.zzoA.getContext());
                }
                uri = parse;
            } catch (zzao e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Unable to append parameter to URL: " + url);
                uri = parse;
            }
            if (this.zzww == null || this.zzww.zzbd()) {
                zza(new AdLauncherIntentInfoParcel("android.intent.action.VIEW", uri.toString(), null, null, null, null, null));
            } else {
                this.zzww.zzo(url);
            }
        }
        return true;
    }

    public void zzD(boolean z) {
        this.zzHd = z;
    }

    public void zza(int i, int i2, boolean z) {
        this.zzHf.zze(i, i2);
        if (this.zzwx != null) {
            this.zzwx.zza(i, i2, z);
        }
    }

    public final void zza(AdLauncherIntentInfoParcel adLauncherIntentInfoParcel) {
        boolean zzgJ = this.zzoA.zzgJ();
        zza(new AdOverlayInfoParcel(adLauncherIntentInfoParcel, (!zzgJ || this.zzoA.zzaN().zzsn) ? this.zzrU : null, zzgJ ? null : this.zzHc, this.zzHe, this.zzoA.zzgI()));
    }

    public void zza(AdOverlayInfoParcel adOverlayInfoParcel) {
        com.google.android.gms.ads.internal.zzo.zzbt().zza(this.zzoA.getContext(), adOverlayInfoParcel, this.zzwx != null ? this.zzwx.zzee() : false ? false : true);
    }

    public void zza(zza zzaVar) {
        this.zzBi = zzaVar;
    }

    public final void zza(String str, zzdg zzdgVar) {
        synchronized (this.zzqt) {
            List<zzdg> list = this.zzHb.get(str);
            if (list == null) {
                list = new CopyOnWriteArrayList<>();
                this.zzHb.put(str, list);
            }
            list.add(zzdgVar);
        }
    }

    public final void zza(boolean z, int i) {
        zza(new AdOverlayInfoParcel((!this.zzoA.zzgJ() || this.zzoA.zzaN().zzsn) ? this.zzrU : null, this.zzHc, this.zzHe, this.zzoA, z, i, this.zzoA.zzgI()));
    }

    public final void zza(boolean z, int i, String str) {
        boolean zzgJ = this.zzoA.zzgJ();
        zza(new AdOverlayInfoParcel((!zzgJ || this.zzoA.zzaN().zzsn) ? this.zzrU : null, zzgJ ? null : new zzb(this.zzoA, this.zzHc), this.zzvU, this.zzHe, this.zzoA, z, i, str, this.zzoA.zzgI(), this.zzwz));
    }

    public final void zza(boolean z, int i, String str, String str2) {
        boolean zzgJ = this.zzoA.zzgJ();
        zza(new AdOverlayInfoParcel((!zzgJ || this.zzoA.zzaN().zzsn) ? this.zzrU : null, zzgJ ? null : new zzb(this.zzoA, this.zzHc), this.zzvU, this.zzHe, this.zzoA, z, i, str, str2, this.zzoA.zzgI(), this.zzwz));
    }

    public void zzb(com.google.android.gms.ads.internal.client.zza zzaVar, com.google.android.gms.ads.internal.overlay.zzf zzfVar, zzde zzdeVar, com.google.android.gms.ads.internal.overlay.zzk zzkVar, boolean z, zzdi zzdiVar, zzdk zzdkVar, com.google.android.gms.ads.internal.zzd zzdVar, zzev zzevVar) {
        if (zzdVar == null) {
            zzdVar = new com.google.android.gms.ads.internal.zzd(false);
        }
        this.zzwx = new zzep(this.zzoA, zzevVar);
        zza("/appEvent", new zzdd(zzdeVar));
        zza("/canOpenURLs", zzdf.zzvW);
        zza("/canOpenIntents", zzdf.zzvX);
        zza("/click", zzdf.zzvY);
        zza("/close", zzdf.zzvZ);
        zza("/customClose", zzdf.zzwa);
        zza("/delayPageLoaded", new zzc());
        zza("/httpTrack", zzdf.zzwb);
        zza("/log", zzdf.zzwc);
        zza("/mraid", new zzdm(zzdVar, this.zzwx));
        zza("/open", new zzdn(zzdiVar, zzdVar, this.zzwx));
        zza("/precache", zzdf.zzwf);
        zza("/touch", zzdf.zzwd);
        zza("/video", zzdf.zzwe);
        if (zzdkVar != null) {
            zza("/setInterstitialProperties", new zzdj(zzdkVar));
        }
        this.zzrU = zzaVar;
        this.zzHc = zzfVar;
        this.zzvU = zzdeVar;
        this.zzwz = zzdiVar;
        this.zzHe = zzkVar;
        this.zzww = zzdVar;
        this.zzyE = zzevVar;
        this.zzwu = zzdkVar;
        zzD(z);
        this.zzHg = false;
    }

    public final void zzb(String str, zzdg zzdgVar) {
        synchronized (this.zzqt) {
            List<zzdg> list = this.zzHb.get(str);
            if (list == null) {
                return;
            }
            list.remove(zzdgVar);
        }
    }

    public boolean zzbU() {
        boolean z;
        synchronized (this.zzqt) {
            z = this.zzqs;
        }
        return z;
    }

    public void zzd(int i, int i2) {
        if (this.zzwx != null) {
            this.zzwx.zzd(i, i2);
        }
    }

    public final void zzet() {
        synchronized (this.zzqt) {
            this.zzHd = false;
            this.zzqs = true;
            this.zzoA.zzgL();
            final com.google.android.gms.ads.internal.overlay.zzc zzgD = this.zzoA.zzgD();
            if (zzgD != null) {
                if (com.google.android.gms.ads.internal.client.zzk.zzcA().zzgw()) {
                    zzgD.zzet();
                } else {
                    zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.internal.zzie.1
                        @Override // java.lang.Runnable
                        public void run() {
                            zzgD.zzet();
                        }
                    });
                }
            }
        }
    }

    public void zzg(Uri uri) {
        String path = uri.getPath();
        List<zzdg> list = this.zzHb.get(path);
        if (list == null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaB("No GMSG handler found for GMSG: " + uri);
            return;
        }
        Map<String, String> zzd = com.google.android.gms.ads.internal.zzo.zzbv().zzd(uri);
        if (com.google.android.gms.ads.internal.util.client.zzb.zzL(2)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaB("Received GMSG: " + path);
            for (String str : zzd.keySet()) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaB("  " + str + ": " + zzd.get(str));
            }
        }
        for (zzdg zzdgVar : list) {
            zzdgVar.zza(this.zzoA, zzd);
        }
    }

    public com.google.android.gms.ads.internal.zzd zzgM() {
        return this.zzww;
    }

    public void zzgN() {
        synchronized (this.zzqt) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaB("Loading blank page in WebView, 2...");
            this.zzHh = true;
            this.zzoA.zzaD("about:blank");
        }
    }

    public final void zzgR() {
        if (this.zzBi != null) {
            if ((!this.zzHi || this.zzHk > 0) && !this.zzHj) {
                return;
            }
            this.zzBi.zza(this.zzoA, !this.zzHj);
            this.zzBi = null;
        }
    }

    public void zzgS() {
        if (zzbU()) {
            this.zzHf.zzek();
        }
    }
}
