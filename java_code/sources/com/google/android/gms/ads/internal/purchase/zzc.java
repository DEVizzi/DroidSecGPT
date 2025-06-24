package com.google.android.gms.ads.internal.purchase;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.SystemClock;
import com.google.android.gms.ads.internal.zzo;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.google.android.gms.internal.zzfj;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzhh;
import com.google.android.gms.internal.zzhl;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
@zzgd
/* loaded from: classes.dex */
public class zzc extends zzhh implements ServiceConnection {
    private Context mContext;
    private boolean zzAC;
    private zzfj zzAD;
    private zzb zzAE;
    private zzh zzAF;
    private List<zzf> zzAG;
    private zzk zzAH;
    private final Object zzqt;

    public zzc(Context context, zzfj zzfjVar, zzk zzkVar) {
        this(context, zzfjVar, zzkVar, new zzb(context), zzh.zzy(context.getApplicationContext()));
    }

    zzc(Context context, zzfj zzfjVar, zzk zzkVar, zzb zzbVar, zzh zzhVar) {
        this.zzqt = new Object();
        this.zzAC = false;
        this.zzAG = null;
        this.mContext = context;
        this.zzAD = zzfjVar;
        this.zzAH = zzkVar;
        this.zzAE = zzbVar;
        this.zzAF = zzhVar;
        this.zzAG = this.zzAF.zzf(10L);
    }

    private void zzd(long j) {
        do {
            if (!zze(j)) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaB("Timeout waiting for pending transaction to be processed.");
            }
        } while (!this.zzAC);
    }

    private boolean zze(long j) {
        long elapsedRealtime = 60000 - (SystemClock.elapsedRealtime() - j);
        if (elapsedRealtime <= 0) {
            return false;
        }
        try {
            this.zzqt.wait(elapsedRealtime);
        } catch (InterruptedException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("waitWithTimeout_lock interrupted");
        }
        return true;
    }

    @Override // android.content.ServiceConnection
    public void onServiceConnected(ComponentName name, IBinder service) {
        synchronized (this.zzqt) {
            this.zzAE.zzK(service);
            zzfe();
            this.zzAC = true;
            this.zzqt.notify();
        }
    }

    @Override // android.content.ServiceConnection
    public void onServiceDisconnected(ComponentName name) {
        com.google.android.gms.ads.internal.util.client.zzb.zzaA("In-app billing service disconnected.");
        this.zzAE.destroy();
    }

    @Override // com.google.android.gms.internal.zzhh
    public void onStop() {
        synchronized (this.zzqt) {
            com.google.android.gms.common.stats.zzb.zzoO().zza(this.mContext, this);
            this.zzAE.destroy();
        }
    }

    protected void zza(final zzf zzfVar, String str, String str2) {
        final Intent intent = new Intent();
        zzo.zzbF();
        intent.putExtra("RESPONSE_CODE", 0);
        zzo.zzbF();
        intent.putExtra("INAPP_PURCHASE_DATA", str);
        zzo.zzbF();
        intent.putExtra("INAPP_DATA_SIGNATURE", str2);
        zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.ads.internal.purchase.zzc.1
            @Override // java.lang.Runnable
            public void run() {
                try {
                    if (zzc.this.zzAH.zza(zzfVar.zzAS, -1, intent)) {
                        zzc.this.zzAD.zza(new zzg(zzc.this.mContext, zzfVar.zzAT, true, -1, intent, zzfVar));
                    } else {
                        zzc.this.zzAD.zza(new zzg(zzc.this.mContext, zzfVar.zzAT, false, -1, intent, zzfVar));
                    }
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzaC("Fail to verify and dispatch pending transaction");
                }
            }
        });
    }

    @Override // com.google.android.gms.internal.zzhh
    public void zzdP() {
        synchronized (this.zzqt) {
            Intent intent = new Intent("com.android.vending.billing.InAppBillingService.BIND");
            intent.setPackage(GooglePlayServicesUtil.GOOGLE_PLAY_STORE_PACKAGE);
            com.google.android.gms.common.stats.zzb.zzoO().zza(this.mContext, intent, this, 1);
            zzd(SystemClock.elapsedRealtime());
            com.google.android.gms.common.stats.zzb.zzoO().zza(this.mContext, this);
            this.zzAE.destroy();
        }
    }

    protected void zzfe() {
        if (this.zzAG.isEmpty()) {
            return;
        }
        HashMap hashMap = new HashMap();
        for (zzf zzfVar : this.zzAG) {
            hashMap.put(zzfVar.zzAT, zzfVar);
        }
        String str = null;
        while (true) {
            Bundle zzi = this.zzAE.zzi(this.mContext.getPackageName(), str);
            if (zzi == null || zzo.zzbF().zzb(zzi) != 0) {
                break;
            }
            ArrayList<String> stringArrayList = zzi.getStringArrayList("INAPP_PURCHASE_ITEM_LIST");
            ArrayList<String> stringArrayList2 = zzi.getStringArrayList("INAPP_PURCHASE_DATA_LIST");
            ArrayList<String> stringArrayList3 = zzi.getStringArrayList("INAPP_DATA_SIGNATURE_LIST");
            String string = zzi.getString("INAPP_CONTINUATION_TOKEN");
            int i = 0;
            while (true) {
                int i2 = i;
                if (i2 >= stringArrayList.size()) {
                    break;
                }
                if (hashMap.containsKey(stringArrayList.get(i2))) {
                    String str2 = stringArrayList.get(i2);
                    String str3 = stringArrayList2.get(i2);
                    String str4 = stringArrayList3.get(i2);
                    zzf zzfVar2 = (zzf) hashMap.get(str2);
                    if (zzfVar2.zzAS.equals(zzo.zzbF().zzai(str3))) {
                        zza(zzfVar2, str3, str4);
                        hashMap.remove(str2);
                    }
                }
                i = i2 + 1;
            }
            if (string == null || hashMap.isEmpty()) {
                break;
            }
            str = string;
        }
        for (String str5 : hashMap.keySet()) {
            this.zzAF.zza((zzf) hashMap.get(str5));
        }
    }
}
