package com.google.android.gms.ads.internal;

import android.content.Context;
import android.os.RemoteException;
import android.view.MotionEvent;
import android.view.View;
import com.google.android.gms.ads.internal.client.AdSizeParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.ads.internal.zzd;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.internal.zzcf;
import com.google.android.gms.internal.zzci;
import com.google.android.gms.internal.zzef;
import com.google.android.gms.internal.zzev;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzha;
import com.google.android.gms.internal.zzid;
@zzgd
/* loaded from: classes.dex */
public abstract class zzc extends zzb implements zzf, zzev {
    public zzc(Context context, AdSizeParcel adSizeParcel, String str, zzef zzefVar, VersionInfoParcel versionInfoParcel) {
        super(context, adSizeParcel, str, zzefVar, versionInfoParcel);
    }

    @Override // com.google.android.gms.ads.internal.zzf
    public void recordClick() {
        onAdClicked();
    }

    @Override // com.google.android.gms.ads.internal.zza, com.google.android.gms.ads.internal.zzf
    public void recordImpression() {
        zza(this.zzon.zzpO, false);
    }

    protected zzid zza(zzd zzdVar) {
        zzid zza;
        View nextView = this.zzon.zzpK.getNextView();
        if (nextView instanceof zzid) {
            zza = (zzid) nextView;
            zza.zza(this.zzon.zzpH, this.zzon.zzpN);
        } else {
            if (nextView != null) {
                this.zzon.zzpK.removeView(nextView);
            }
            zza = zzo.zzbw().zza(this.zzon.zzpH, this.zzon.zzpN, false, false, this.zzon.zzpI, this.zzon.zzpJ);
            if (this.zzon.zzpN.zzso == null) {
                zzb(zza.getWebView());
            }
        }
        zza.zzgF().zzb(this, this, this, this, false, this, null, zzdVar, this);
        return zza;
    }

    @Override // com.google.android.gms.internal.zzev
    public void zza(int i, int i2, int i3, int i4) {
        zzaS();
    }

    @Override // com.google.android.gms.ads.internal.zza, com.google.android.gms.ads.internal.client.zzr
    public void zza(zzci zzciVar) {
        zzu.zzbY("setOnCustomRenderedAdLoadedListener must be called on the main UI thread.");
        this.zzon.zzqc = zzciVar;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.ads.internal.zzb, com.google.android.gms.ads.internal.zza
    public boolean zza(zzha zzhaVar, zzha zzhaVar2) {
        if (this.zzon.zzbM() && this.zzon.zzpK != null) {
            this.zzon.zzpK.zzbP().zzaw(zzhaVar2.zzCP);
        }
        return super.zza(zzhaVar, zzhaVar2);
    }

    @Override // com.google.android.gms.ads.internal.zza
    protected boolean zzb(zzha.zza zzaVar) {
        final zzd zzdVar = new zzd();
        zzid zza = zza(zzdVar);
        zzdVar.zza(new zzd.zzb(zzaVar, zza));
        zza.setOnTouchListener(new View.OnTouchListener() { // from class: com.google.android.gms.ads.internal.zzc.1
            @Override // android.view.View.OnTouchListener
            public boolean onTouch(View v, MotionEvent event) {
                zzdVar.recordClick();
                return false;
            }
        });
        zza.setOnClickListener(new View.OnClickListener() { // from class: com.google.android.gms.ads.internal.zzc.2
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                zzdVar.recordClick();
            }
        });
        if (zzaVar.zzpN != null) {
            this.zzon.zzpN = zzaVar.zzpN;
        }
        if (zzaVar.errorCode != -2) {
            zzb(new zzha(zzaVar, zza, null, null, null, null, null));
            return false;
        }
        if (!zzaVar.zzFs.zzCK && zzaVar.zzFs.zzCT) {
            zzcf zzcfVar = new zzcf(this, zzaVar.zzFs.zzzG != null ? zzo.zzbv().zzat(zzaVar.zzFs.zzzG) : null, zzaVar.zzFs.zzCI);
            try {
                if (this.zzon.zzqc != null) {
                    this.zzon.zzqh = 1;
                    this.zzon.zzqc.zza(zzcfVar);
                    return false;
                }
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call the onCustomRenderedAdLoadedListener.", e);
            }
        }
        this.zzon.zzqh = 0;
        this.zzon.zzpM = zzo.zzbu().zza(this.zzon.zzpH, this, zzaVar, this.zzon.zzpI, zza, this.zzoq, this);
        return true;
    }

    @Override // com.google.android.gms.internal.zzev
    public void zzbc() {
        zzaQ();
    }

    @Override // com.google.android.gms.ads.internal.zzf
    public void zzc(View view) {
        this.zzon.zzqg = view;
        zzb(new zzha(this.zzon.zzpP, null, null, null, null, null, null));
    }
}
