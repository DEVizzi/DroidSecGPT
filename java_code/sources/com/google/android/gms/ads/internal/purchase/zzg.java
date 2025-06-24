package com.google.android.gms.ads.internal.purchase;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import com.google.android.gms.ads.internal.zzo;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.google.android.gms.internal.zzfi;
import com.google.android.gms.internal.zzgd;
@zzgd
/* loaded from: classes.dex */
public final class zzg extends zzfi.zza implements ServiceConnection {
    private Context mContext;
    zzb zzAE;
    private String zzAK;
    private zzf zzAO;
    private boolean zzAU;
    private int zzAV;
    private Intent zzAW;

    public zzg(Context context, String str, boolean z, int i, Intent intent, zzf zzfVar) {
        this.zzAU = false;
        this.zzAK = str;
        this.zzAV = i;
        this.zzAW = intent;
        this.zzAU = z;
        this.mContext = context;
        this.zzAO = zzfVar;
    }

    @Override // com.google.android.gms.internal.zzfi
    public void finishPurchase() {
        int zzd = zzo.zzbF().zzd(this.zzAW);
        if (this.zzAV == -1 && zzd == 0) {
            this.zzAE = new zzb(this.mContext);
            Intent intent = new Intent("com.android.vending.billing.InAppBillingService.BIND");
            intent.setPackage(GooglePlayServicesUtil.GOOGLE_PLAY_STORE_PACKAGE);
            com.google.android.gms.common.stats.zzb.zzoO().zza(this.mContext, intent, this, 1);
        }
    }

    @Override // com.google.android.gms.internal.zzfi
    public String getProductId() {
        return this.zzAK;
    }

    @Override // com.google.android.gms.internal.zzfi
    public Intent getPurchaseData() {
        return this.zzAW;
    }

    @Override // com.google.android.gms.internal.zzfi
    public int getResultCode() {
        return this.zzAV;
    }

    @Override // com.google.android.gms.internal.zzfi
    public boolean isVerified() {
        return this.zzAU;
    }

    @Override // android.content.ServiceConnection
    public void onServiceConnected(ComponentName name, IBinder service) {
        com.google.android.gms.ads.internal.util.client.zzb.zzaA("In-app billing service connected.");
        this.zzAE.zzK(service);
        String zzaj = zzo.zzbF().zzaj(zzo.zzbF().zze(this.zzAW));
        if (zzaj == null) {
            return;
        }
        if (this.zzAE.zzh(this.mContext.getPackageName(), zzaj) == 0) {
            zzh.zzy(this.mContext).zza(this.zzAO);
        }
        com.google.android.gms.common.stats.zzb.zzoO().zza(this.mContext, this);
        this.zzAE.destroy();
    }

    @Override // android.content.ServiceConnection
    public void onServiceDisconnected(ComponentName name) {
        com.google.android.gms.ads.internal.util.client.zzb.zzaA("In-app billing service disconnected.");
        this.zzAE.destroy();
    }
}
