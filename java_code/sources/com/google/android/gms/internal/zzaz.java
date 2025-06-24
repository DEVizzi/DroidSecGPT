package com.google.android.gms.internal;

import android.app.KeyguardManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Rect;
import android.os.PowerManager;
import android.text.TextUtils;
import android.util.DisplayMetrics;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.WindowManager;
import com.google.android.gms.ads.internal.client.AdSizeParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.zzdt;
import com.google.android.gms.internal.zzhx;
import java.lang.ref.WeakReference;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
@zzgd
/* loaded from: classes.dex */
public class zzaz implements ViewTreeObserver.OnGlobalLayoutListener, ViewTreeObserver.OnScrollChangedListener {
    private final WeakReference<View> zzqA;
    private final zzax zzqB;
    private final zzdt zzqC;
    private final zzdt.zzd zzqD;
    private boolean zzqE;
    private final WindowManager zzqF;
    private final PowerManager zzqG;
    private final KeyguardManager zzqH;
    private zzba zzqI;
    private boolean zzqJ;
    private boolean zzqM;
    private BroadcastReceiver zzqN;
    private final Context zzqw;
    private final WeakReference<zzha> zzqy;
    private final Object zzqt = new Object();
    private boolean zzpj = false;
    private boolean zzqK = false;
    private final HashSet<zzaw> zzqO = new HashSet<>();
    private final zzdg zzqP = new zzdg() { // from class: com.google.android.gms.internal.zzaz.6
        @Override // com.google.android.gms.internal.zzdg
        public void zza(zzid zzidVar, Map<String, String> map) {
            if (zzaz.this.zzb(map)) {
                zzaz.this.zza(zzidVar.getWebView(), map);
            }
        }
    };
    private final zzdg zzqQ = new zzdg() { // from class: com.google.android.gms.internal.zzaz.7
        @Override // com.google.android.gms.internal.zzdg
        public void zza(zzid zzidVar, Map<String, String> map) {
            if (zzaz.this.zzb(map)) {
                com.google.android.gms.ads.internal.util.client.zzb.zzay("Received request to untrack: " + zzaz.this.zzqB.zzbT());
                zzaz.this.destroy();
            }
        }
    };
    private final zzdg zzqR = new zzdg() { // from class: com.google.android.gms.internal.zzaz.8
        @Override // com.google.android.gms.internal.zzdg
        public void zza(zzid zzidVar, Map<String, String> map) {
            if (zzaz.this.zzb(map) && map.containsKey("isVisible")) {
                zzaz.this.zzg(Boolean.valueOf("1".equals(map.get("isVisible")) || "true".equals(map.get("isVisible"))).booleanValue());
            }
        }
    };
    private WeakReference<ViewTreeObserver> zzqz = new WeakReference<>(null);
    private boolean zzqL = true;
    private zzhq zzqm = new zzhq(200);

    public zzaz(AdSizeParcel adSizeParcel, zzha zzhaVar, VersionInfoParcel versionInfoParcel, View view, zzdt zzdtVar) {
        this.zzqC = zzdtVar;
        this.zzqy = new WeakReference<>(zzhaVar);
        this.zzqA = new WeakReference<>(view);
        this.zzqB = new zzax(UUID.randomUUID().toString(), versionInfoParcel, adSizeParcel.zzsm, zzhaVar.zzFl, zzhaVar.zzbU());
        this.zzqD = this.zzqC.zzdU();
        this.zzqF = (WindowManager) view.getContext().getSystemService("window");
        this.zzqG = (PowerManager) view.getContext().getApplicationContext().getSystemService("power");
        this.zzqH = (KeyguardManager) view.getContext().getSystemService("keyguard");
        this.zzqw = view.getContext().getApplicationContext();
        try {
            final JSONObject zzd = zzd(view);
            this.zzqD.zza(new zzhx.zzc<zzbe>() { // from class: com.google.android.gms.internal.zzaz.1
                @Override // com.google.android.gms.internal.zzhx.zzc
                /* renamed from: zzb */
                public void zzc(zzbe zzbeVar) {
                    zzaz.this.zza(zzd);
                }
            }, new zzhx.zza() { // from class: com.google.android.gms.internal.zzaz.2
                @Override // com.google.android.gms.internal.zzhx.zza
                public void run() {
                }
            });
        } catch (RuntimeException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzb("Failure while processing active view data.", e);
        } catch (JSONException e2) {
        }
        this.zzqD.zza(new zzhx.zzc<zzbe>() { // from class: com.google.android.gms.internal.zzaz.3
            @Override // com.google.android.gms.internal.zzhx.zzc
            /* renamed from: zzb */
            public void zzc(zzbe zzbeVar) {
                zzaz.this.zzqE = true;
                zzaz.this.zza(zzbeVar);
                zzaz.this.zzbV();
                zzaz.this.zzh(false);
            }
        }, new zzhx.zza() { // from class: com.google.android.gms.internal.zzaz.4
            @Override // com.google.android.gms.internal.zzhx.zza
            public void run() {
                zzaz.this.destroy();
            }
        });
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Tracking ad unit: " + this.zzqB.zzbT());
    }

    protected void destroy() {
        synchronized (this.zzqt) {
            zzcb();
            zzbW();
            this.zzqL = false;
            zzbY();
            this.zzqD.release();
        }
    }

    boolean isScreenOn() {
        return this.zzqG.isScreenOn();
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public void onGlobalLayout() {
        zzh(false);
    }

    @Override // android.view.ViewTreeObserver.OnScrollChangedListener
    public void onScrollChanged() {
        zzh(true);
    }

    public void pause() {
        synchronized (this.zzqt) {
            this.zzpj = true;
            zzh(false);
        }
    }

    public void resume() {
        synchronized (this.zzqt) {
            this.zzpj = false;
            zzh(false);
        }
    }

    public void stop() {
        synchronized (this.zzqt) {
            this.zzqK = true;
            zzh(false);
        }
    }

    protected int zza(int i, DisplayMetrics displayMetrics) {
        return (int) (i / displayMetrics.density);
    }

    protected void zza(View view, Map<String, String> map) {
        zzh(false);
    }

    public void zza(zzaw zzawVar) {
        this.zzqO.add(zzawVar);
    }

    public void zza(zzba zzbaVar) {
        synchronized (this.zzqt) {
            this.zzqI = zzbaVar;
        }
    }

    protected void zza(zzbe zzbeVar) {
        zzbeVar.zza("/updateActiveView", this.zzqP);
        zzbeVar.zza("/untrackActiveViewUnit", this.zzqQ);
        zzbeVar.zza("/visibilityChanged", this.zzqR);
    }

    protected void zza(JSONObject jSONObject) {
        try {
            JSONArray jSONArray = new JSONArray();
            final JSONObject jSONObject2 = new JSONObject();
            jSONArray.put(jSONObject);
            jSONObject2.put("units", jSONArray);
            this.zzqD.zza(new zzhx.zzc<zzbe>() { // from class: com.google.android.gms.internal.zzaz.9
                @Override // com.google.android.gms.internal.zzhx.zzc
                /* renamed from: zzb */
                public void zzc(zzbe zzbeVar) {
                    zzbeVar.zza("AFMA_updateActiveView", jSONObject2);
                }
            }, new zzhx.zzb());
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzb("Skipping active view message.", th);
        }
    }

    protected boolean zzb(Map<String, String> map) {
        if (map == null) {
            return false;
        }
        String str = map.get("hashCode");
        return !TextUtils.isEmpty(str) && str.equals(this.zzqB.zzbT());
    }

    protected void zzbV() {
        synchronized (this.zzqt) {
            if (this.zzqN != null) {
                return;
            }
            IntentFilter intentFilter = new IntentFilter();
            intentFilter.addAction("android.intent.action.SCREEN_ON");
            intentFilter.addAction("android.intent.action.SCREEN_OFF");
            this.zzqN = new BroadcastReceiver() { // from class: com.google.android.gms.internal.zzaz.5
                @Override // android.content.BroadcastReceiver
                public void onReceive(Context context, Intent intent) {
                    zzaz.this.zzh(false);
                }
            };
            this.zzqw.registerReceiver(this.zzqN, intentFilter);
        }
    }

    protected void zzbW() {
        synchronized (this.zzqt) {
            if (this.zzqN != null) {
                this.zzqw.unregisterReceiver(this.zzqN);
                this.zzqN = null;
            }
        }
    }

    public void zzbX() {
        synchronized (this.zzqt) {
            if (this.zzqL) {
                this.zzqM = true;
                try {
                    try {
                        zza(zzcd());
                    } catch (RuntimeException e) {
                        com.google.android.gms.ads.internal.util.client.zzb.zzb("Failure while processing active view data.", e);
                    }
                } catch (JSONException e2) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzb("JSON failure while processing active view data.", e2);
                }
                com.google.android.gms.ads.internal.util.client.zzb.zzay("Untracking ad unit: " + this.zzqB.zzbT());
            }
        }
    }

    protected void zzbY() {
        if (this.zzqI != null) {
            this.zzqI.zza(this);
        }
    }

    public boolean zzbZ() {
        boolean z;
        synchronized (this.zzqt) {
            z = this.zzqL;
        }
        return z;
    }

    protected void zzca() {
        ViewTreeObserver viewTreeObserver;
        ViewTreeObserver viewTreeObserver2;
        View view = this.zzqA.get();
        if (view == null || (viewTreeObserver2 = view.getViewTreeObserver()) == (viewTreeObserver = this.zzqz.get())) {
            return;
        }
        zzcb();
        if (!this.zzqJ || (viewTreeObserver != null && viewTreeObserver.isAlive())) {
            this.zzqJ = true;
            viewTreeObserver2.addOnScrollChangedListener(this);
            viewTreeObserver2.addOnGlobalLayoutListener(this);
        }
        this.zzqz = new WeakReference<>(viewTreeObserver2);
    }

    protected void zzcb() {
        ViewTreeObserver viewTreeObserver = this.zzqz.get();
        if (viewTreeObserver == null || !viewTreeObserver.isAlive()) {
            return;
        }
        viewTreeObserver.removeOnScrollChangedListener(this);
        viewTreeObserver.removeGlobalOnLayoutListener(this);
    }

    protected JSONObject zzcc() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("afmaVersion", this.zzqB.zzbR()).put("activeViewJSON", this.zzqB.zzbS()).put("timestamp", com.google.android.gms.ads.internal.zzo.zzbz().elapsedRealtime()).put("adFormat", this.zzqB.zzbQ()).put("hashCode", this.zzqB.zzbT()).put("isMraid", this.zzqB.zzbU());
        return jSONObject;
    }

    protected JSONObject zzcd() throws JSONException {
        JSONObject zzcc = zzcc();
        zzcc.put("doneReasonCode", "u");
        return zzcc;
    }

    protected JSONObject zzd(View view) throws JSONException {
        boolean zzk = com.google.android.gms.ads.internal.zzo.zzbx().zzk(view);
        int[] iArr = new int[2];
        int[] iArr2 = new int[2];
        try {
            view.getLocationOnScreen(iArr);
            view.getLocationInWindow(iArr2);
        } catch (Exception e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzb("Failure getting view location.", e);
        }
        DisplayMetrics displayMetrics = view.getContext().getResources().getDisplayMetrics();
        Rect rect = new Rect();
        rect.left = iArr[0];
        rect.top = iArr[1];
        rect.right = rect.left + view.getWidth();
        rect.bottom = rect.top + view.getHeight();
        Rect rect2 = new Rect();
        rect2.right = this.zzqF.getDefaultDisplay().getWidth();
        rect2.bottom = this.zzqF.getDefaultDisplay().getHeight();
        Rect rect3 = new Rect();
        boolean globalVisibleRect = view.getGlobalVisibleRect(rect3, null);
        Rect rect4 = new Rect();
        boolean localVisibleRect = view.getLocalVisibleRect(rect4);
        Rect rect5 = new Rect();
        view.getHitRect(rect5);
        JSONObject zzcc = zzcc();
        zzcc.put("windowVisibility", view.getWindowVisibility()).put("isStopped", this.zzqK).put("isPaused", this.zzpj).put("isAttachedToWindow", zzk).put("viewBox", new JSONObject().put("top", zza(rect2.top, displayMetrics)).put("bottom", zza(rect2.bottom, displayMetrics)).put("left", zza(rect2.left, displayMetrics)).put("right", zza(rect2.right, displayMetrics))).put("adBox", new JSONObject().put("top", zza(rect.top, displayMetrics)).put("bottom", zza(rect.bottom, displayMetrics)).put("left", zza(rect.left, displayMetrics)).put("right", zza(rect.right, displayMetrics))).put("globalVisibleBox", new JSONObject().put("top", zza(rect3.top, displayMetrics)).put("bottom", zza(rect3.bottom, displayMetrics)).put("left", zza(rect3.left, displayMetrics)).put("right", zza(rect3.right, displayMetrics))).put("globalVisibleBoxVisible", globalVisibleRect).put("localVisibleBox", new JSONObject().put("top", zza(rect4.top, displayMetrics)).put("bottom", zza(rect4.bottom, displayMetrics)).put("left", zza(rect4.left, displayMetrics)).put("right", zza(rect4.right, displayMetrics))).put("localVisibleBoxVisible", localVisibleRect).put("hitBox", new JSONObject().put("top", zza(rect5.top, displayMetrics)).put("bottom", zza(rect5.bottom, displayMetrics)).put("left", zza(rect5.left, displayMetrics)).put("right", zza(rect5.right, displayMetrics))).put("screenDensity", displayMetrics.density).put("isVisible", zze(view));
        return zzcc;
    }

    protected boolean zze(View view) {
        return view.getVisibility() == 0 && view.isShown() && isScreenOn() && (!this.zzqH.inKeyguardRestrictedInputMode() || com.google.android.gms.ads.internal.zzo.zzbv().zzgl());
    }

    protected void zzg(boolean z) {
        Iterator<zzaw> it = this.zzqO.iterator();
        while (it.hasNext()) {
            it.next().zza(this, z);
        }
    }

    protected void zzh(boolean z) {
        synchronized (this.zzqt) {
            if (this.zzqE && this.zzqL) {
                if (!z || this.zzqm.tryAcquire()) {
                    zzha zzhaVar = this.zzqy.get();
                    View view = this.zzqA.get();
                    if (view == null || zzhaVar == null) {
                        zzbX();
                        return;
                    }
                    try {
                        zza(zzd(view));
                    } catch (RuntimeException | JSONException e) {
                        com.google.android.gms.ads.internal.util.client.zzb.zza("Active view update failed.", e);
                    }
                    zzca();
                    zzbY();
                }
            }
        }
    }
}
