package com.google.android.gms.ads.internal.formats;

import android.content.Context;
import android.graphics.Rect;
import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout;
import com.google.android.gms.ads.internal.zzm;
import com.google.android.gms.internal.zzan;
import com.google.android.gms.internal.zzbb;
import com.google.android.gms.internal.zzgd;
import org.json.JSONException;
import org.json.JSONObject;
@zzgd
/* loaded from: classes.dex */
public class zzg {
    private final Context mContext;
    private final Object zzqt = new Object();
    private final zzan zzvA;
    private boolean zzvB;
    private final zzm zzvw;
    private final JSONObject zzvx;
    private final zzbb zzvy;
    private final zza zzvz;

    /* loaded from: classes.dex */
    public interface zza {
        String getCustomTemplateId();

        void zza(zzg zzgVar);

        String zzdE();

        com.google.android.gms.ads.internal.formats.zza zzdF();
    }

    public zzg(Context context, zzm zzmVar, zzbb zzbbVar, zzan zzanVar, JSONObject jSONObject, zza zzaVar) {
        this.mContext = context;
        this.zzvw = zzmVar;
        this.zzvy = zzbbVar;
        this.zzvA = zzanVar;
        this.zzvx = jSONObject;
        this.zzvz = zzaVar;
    }

    public void performClick(String assetId) {
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("asset", assetId);
            jSONObject.put("template", this.zzvz.zzdE());
            JSONObject jSONObject2 = new JSONObject();
            jSONObject2.put("ad", this.zzvx);
            jSONObject2.put("click", jSONObject);
            jSONObject2.put("has_custom_click_handler", this.zzvw.zzq(this.zzvz.getCustomTemplateId()) != null);
            this.zzvy.zza("google.afma.nativeAds.handleClickGmsg", jSONObject2);
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzb("Unable to create click JSON.", e);
        }
    }

    public void recordImpression() {
        this.zzvB = true;
        this.zzvw.zzaP();
    }

    public zzb zza(View.OnClickListener onClickListener) {
        com.google.android.gms.ads.internal.formats.zza zzdF = this.zzvz.zzdF();
        if (zzdF == null) {
            return null;
        }
        zzb zzbVar = new zzb(this.mContext, zzdF);
        zzbVar.setLayoutParams(new FrameLayout.LayoutParams(-1, -1));
        zzbVar.zzdv().setOnClickListener(onClickListener);
        return zzbVar;
    }

    public void zzb(MotionEvent motionEvent) {
        this.zzvA.zza(motionEvent);
    }

    public void zzh(View view) {
        synchronized (this.zzqt) {
            if (this.zzvB) {
                return;
            }
            if (view.isShown()) {
                if (view.getGlobalVisibleRect(new Rect(), null)) {
                    recordImpression();
                }
            }
        }
    }
}
