package com.google.android.gms.internal;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import com.google.android.gms.internal.zzqn;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
/* loaded from: classes.dex */
public class zzqo implements Runnable {
    private final Context mContext;
    private final zzqm zzaMS;
    private final zzqd zzaPU;
    private final zzqn zzaQb;
    private final zzqi zzaQc;

    public zzqo(Context context, zzqd zzqdVar, zzqn zzqnVar) {
        this(context, zzqdVar, zzqnVar, new zzqm(), new zzqi());
    }

    zzqo(Context context, zzqd zzqdVar, zzqn zzqnVar, zzqm zzqmVar, zzqi zzqiVar) {
        com.google.android.gms.common.internal.zzu.zzu(context);
        com.google.android.gms.common.internal.zzu.zzu(zzqnVar);
        this.mContext = context;
        this.zzaPU = zzqdVar;
        this.zzaQb = zzqnVar;
        this.zzaMS = zzqmVar;
        this.zzaQc = zzqiVar;
    }

    public zzqo(Context context, zzqd zzqdVar, zzqn zzqnVar, String str) {
        this(context, zzqdVar, zzqnVar, new zzqm(), new zzqi());
        this.zzaQc.zzeU(str);
    }

    @Override // java.lang.Runnable
    public void run() {
        zzeH();
    }

    boolean zzAI() {
        if (!zzba("android.permission.INTERNET")) {
            com.google.android.gms.tagmanager.zzbg.zzaz("Missing android.permission.INTERNET. Please add the following declaration to your AndroidManifest.xml: <uses-permission android:name=\"android.permission.INTERNET\" />");
            return false;
        } else if (!zzba("android.permission.ACCESS_NETWORK_STATE")) {
            com.google.android.gms.tagmanager.zzbg.zzaz("Missing android.permission.ACCESS_NETWORK_STATE. Please add the following declaration to your AndroidManifest.xml: <uses-permission android:name=\"android.permission.ACCESS_NETWORK_STATE\" />");
            return false;
        } else {
            NetworkInfo activeNetworkInfo = ((ConnectivityManager) this.mContext.getSystemService("connectivity")).getActiveNetworkInfo();
            if (activeNetworkInfo == null || !activeNetworkInfo.isConnected()) {
                com.google.android.gms.tagmanager.zzbg.zzaC("NetworkLoader: No network connectivity - Offline");
                return false;
            }
            return true;
        }
    }

    boolean zzba(String str) {
        return this.mContext.getPackageManager().checkPermission(str, this.mContext.getPackageName()) == 0;
    }

    void zzeH() {
        if (!zzAI()) {
            this.zzaQb.zza(zzqn.zza.NOT_AVAILABLE);
            return;
        }
        com.google.android.gms.tagmanager.zzbg.zzaB("NetworkLoader: Starting to load resource from Network.");
        zzql zzAG = this.zzaMS.zzAG();
        try {
            String zzt = this.zzaQc.zzt(this.zzaPU.zzAf());
            try {
                InputStream zzfd = zzAG.zzfd(zzt);
                try {
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    zzlg.zza(zzfd, byteArrayOutputStream);
                    this.zzaQb.zzu(byteArrayOutputStream.toByteArray());
                    zzAG.close();
                    com.google.android.gms.tagmanager.zzbg.zzaB("NetworkLoader: Resource loaded.");
                } catch (IOException e) {
                    com.google.android.gms.tagmanager.zzbg.zzb("NetworkLoader: Error when parsing downloaded resources from url: " + zzt + " " + e.getMessage(), e);
                    this.zzaQb.zza(zzqn.zza.SERVER_ERROR);
                    zzAG.close();
                }
            } catch (FileNotFoundException e2) {
                com.google.android.gms.tagmanager.zzbg.zzaz("NetworkLoader: No data is retrieved from the given url: " + zzt);
                this.zzaQb.zza(zzqn.zza.SERVER_ERROR);
                zzAG.close();
            } catch (IOException e3) {
                com.google.android.gms.tagmanager.zzbg.zzb("NetworkLoader: Error when loading resource from url: " + zzt + " " + e3.getMessage(), e3);
                this.zzaQb.zza(zzqn.zza.IO_ERROR);
                zzAG.close();
            }
        } catch (Throwable th) {
            zzAG.close();
            throw th;
        }
    }
}
