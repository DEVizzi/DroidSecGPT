package com.google.android.gms.ads.internal.formats;

import android.view.MotionEvent;
import android.view.View;
import android.view.ViewTreeObserver;
import android.widget.FrameLayout;
import com.google.android.gms.internal.zzcm;
import com.google.android.gms.internal.zzhz;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
public class zzi extends zzcm.zza implements View.OnClickListener, View.OnTouchListener, ViewTreeObserver.OnGlobalLayoutListener, ViewTreeObserver.OnScrollChangedListener {
    private final FrameLayout zznV;
    private final FrameLayout zzvF;
    private zzb zzvH;
    private zzg zzvq;
    private final Object zzqt = new Object();
    private final Map<String, WeakReference<View>> zzvG = new HashMap();

    public zzi(FrameLayout frameLayout, FrameLayout frameLayout2) {
        this.zzvF = frameLayout;
        this.zznV = frameLayout2;
        zzhz.zza((View) this.zzvF, (ViewTreeObserver.OnGlobalLayoutListener) this);
        zzhz.zza((View) this.zzvF, (ViewTreeObserver.OnScrollChangedListener) this);
        this.zzvF.setOnTouchListener(this);
    }

    private String zzi(View view) {
        synchronized (this.zzqt) {
            if (this.zzvH == null || !this.zzvH.zzdv().equals(view)) {
                for (Map.Entry<String, WeakReference<View>> entry : this.zzvG.entrySet()) {
                    if (view.equals(entry.getValue().get())) {
                        return entry.getKey();
                    }
                }
                return null;
            }
            return "1007";
        }
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        synchronized (this.zzqt) {
            if (this.zzvq == null) {
                return;
            }
            String zzi = zzi(view);
            if (zzi != null) {
                this.zzvq.performClick(zzi);
            }
        }
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public void onGlobalLayout() {
        synchronized (this.zzqt) {
            if (this.zzvq != null) {
                this.zzvq.zzh(this.zzvF);
            }
        }
    }

    @Override // android.view.ViewTreeObserver.OnScrollChangedListener
    public void onScrollChanged() {
        synchronized (this.zzqt) {
            if (this.zzvq != null) {
                this.zzvq.zzh(this.zzvF);
            }
        }
    }

    @Override // android.view.View.OnTouchListener
    public boolean onTouch(View view, MotionEvent motionEvent) {
        boolean z;
        synchronized (this.zzqt) {
            if (this.zzvq == null) {
                z = false;
            } else {
                this.zzvq.zzb(motionEvent);
                z = true;
            }
        }
        return z;
    }

    @Override // com.google.android.gms.internal.zzcm
    public com.google.android.gms.dynamic.zzd zzS(String str) {
        com.google.android.gms.dynamic.zzd zzw;
        synchronized (this.zzqt) {
            WeakReference<View> weakReference = this.zzvG.get(str);
            zzw = com.google.android.gms.dynamic.zze.zzw(weakReference == null ? null : weakReference.get());
        }
        return zzw;
    }

    @Override // com.google.android.gms.internal.zzcm
    public void zza(String str, com.google.android.gms.dynamic.zzd zzdVar) {
        View view = (View) com.google.android.gms.dynamic.zze.zzn(zzdVar);
        synchronized (this.zzqt) {
            if (view == null) {
                this.zzvG.remove(str);
            } else {
                this.zzvG.put(str, new WeakReference<>(view));
                view.setOnClickListener(this);
            }
        }
    }

    @Override // com.google.android.gms.internal.zzcm
    public void zzb(com.google.android.gms.dynamic.zzd zzdVar) {
        synchronized (this.zzqt) {
            this.zzvq = (zzg) com.google.android.gms.dynamic.zze.zzn(zzdVar);
            this.zznV.removeAllViews();
            this.zzvH = zzdI();
            if (this.zzvH != null) {
                this.zznV.addView(this.zzvH);
            }
        }
    }

    zzb zzdI() {
        return this.zzvq.zza(this);
    }
}
