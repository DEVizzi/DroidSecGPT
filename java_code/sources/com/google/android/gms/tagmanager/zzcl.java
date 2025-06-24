package com.google.android.gms.tagmanager;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import com.google.android.gms.internal.zzaf;
import com.google.android.gms.internal.zzqf;
import com.google.android.gms.internal.zzql;
import com.google.android.gms.internal.zzqm;
import com.google.android.gms.tagmanager.zzbf;
import com.google.android.gms.tagmanager.zzcb;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
/* loaded from: classes.dex */
class zzcl implements Runnable {
    private final Context mContext;
    private volatile String zzaKV;
    private final String zzaKy;
    private final zzqm zzaMS;
    private final String zzaMT;
    private zzbf<zzaf.zzj> zzaMU;
    private volatile zzs zzaMV;
    private volatile String zzaMW;

    zzcl(Context context, String str, zzqm zzqmVar, zzs zzsVar) {
        this.mContext = context;
        this.zzaMS = zzqmVar;
        this.zzaKy = str;
        this.zzaMV = zzsVar;
        this.zzaMT = "/r?id=" + str;
        this.zzaKV = this.zzaMT;
        this.zzaMW = null;
    }

    public zzcl(Context context, String str, zzs zzsVar) {
        this(context, str, new zzqm(), zzsVar);
    }

    private boolean zzzi() {
        NetworkInfo activeNetworkInfo = ((ConnectivityManager) this.mContext.getSystemService("connectivity")).getActiveNetworkInfo();
        if (activeNetworkInfo == null || !activeNetworkInfo.isConnected()) {
            zzbg.zzaB("...no network connectivity");
            return false;
        }
        return true;
    }

    private void zzzj() {
        if (!zzzi()) {
            this.zzaMU.zza(zzbf.zza.NOT_AVAILABLE);
            return;
        }
        zzbg.zzaB("Start loading resource from network ...");
        String zzzk = zzzk();
        zzql zzAG = this.zzaMS.zzAG();
        try {
            try {
                InputStream zzfd = zzAG.zzfd(zzzk);
                try {
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    zzqf.zzc(zzfd, byteArrayOutputStream);
                    zzaf.zzj zzd = zzaf.zzj.zzd(byteArrayOutputStream.toByteArray());
                    zzbg.zzaB("Successfully loaded supplemented resource: " + zzd);
                    if (zzd.zziO == null && zzd.zziN.length == 0) {
                        zzbg.zzaB("No change for container: " + this.zzaKy);
                    }
                    this.zzaMU.zzz(zzd);
                    zzAG.close();
                    zzbg.zzaB("Load resource from network finished.");
                } catch (IOException e) {
                    zzbg.zzd("Error when parsing downloaded resources from url: " + zzzk + " " + e.getMessage(), e);
                    this.zzaMU.zza(zzbf.zza.SERVER_ERROR);
                    zzAG.close();
                }
            } catch (FileNotFoundException e2) {
                zzbg.zzaC("No data is retrieved from the given url: " + zzzk + ". Make sure container_id: " + this.zzaKy + " is correct.");
                this.zzaMU.zza(zzbf.zza.SERVER_ERROR);
                zzAG.close();
            } catch (IOException e3) {
                zzbg.zzd("Error when loading resources from url: " + zzzk + " " + e3.getMessage(), e3);
                this.zzaMU.zza(zzbf.zza.IO_ERROR);
                zzAG.close();
            }
        } catch (Throwable th) {
            zzAG.close();
            throw th;
        }
    }

    @Override // java.lang.Runnable
    public void run() {
        if (this.zzaMU == null) {
            throw new IllegalStateException("callback must be set before execute");
        }
        this.zzaMU.zzyv();
        zzzj();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zza(zzbf<zzaf.zzj> zzbfVar) {
        this.zzaMU = zzbfVar;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zzeB(String str) {
        zzbg.zzay("Setting previous container version: " + str);
        this.zzaMW = str;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zzem(String str) {
        if (str == null) {
            this.zzaKV = this.zzaMT;
            return;
        }
        zzbg.zzay("Setting CTFE URL path: " + str);
        this.zzaKV = str;
    }

    String zzzk() {
        String str = this.zzaMV.zzyx() + this.zzaKV + "&v=a65833898";
        if (this.zzaMW != null && !this.zzaMW.trim().equals("")) {
            str = str + "&pv=" + this.zzaMW;
        }
        return zzcb.zzzf().zzzg().equals(zzcb.zza.CONTAINER_DEBUG) ? str + "&gtm_debug=x" : str;
    }
}
