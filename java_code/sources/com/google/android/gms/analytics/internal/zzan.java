package com.google.android.gms.analytics.internal;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.support.v7.media.MediaRouteProviderProtocol;
/* loaded from: classes.dex */
public class zzan extends zzd {
    protected boolean zzIx;
    protected int zzKR;
    protected String zzLU;
    protected String zzLV;
    protected int zzLX;
    protected boolean zzML;
    protected boolean zzMM;
    protected boolean zzMN;

    public zzan(zzf zzfVar) {
        super(zzfVar);
    }

    private static int zzbo(String str) {
        String lowerCase = str.toLowerCase();
        if ("verbose".equals(lowerCase)) {
            return 0;
        }
        if ("info".equals(lowerCase)) {
            return 1;
        }
        if ("warning".equals(lowerCase)) {
            return 2;
        }
        return MediaRouteProviderProtocol.SERVICE_DATA_ERROR.equals(lowerCase) ? 3 : -1;
    }

    public int getLogLevel() {
        zzia();
        return this.zzKR;
    }

    void zza(zzaa zzaaVar) {
        int zzbo;
        zzaT("Loading global XML config values");
        if (zzaaVar.zzjK()) {
            String zzjL = zzaaVar.zzjL();
            this.zzLU = zzjL;
            zzb("XML config - app name", zzjL);
        }
        if (zzaaVar.zzjM()) {
            String zzjN = zzaaVar.zzjN();
            this.zzLV = zzjN;
            zzb("XML config - app version", zzjN);
        }
        if (zzaaVar.zzjO() && (zzbo = zzbo(zzaaVar.zzjP())) >= 0) {
            this.zzKR = zzbo;
            zza("XML config - log level", Integer.valueOf(zzbo));
        }
        if (zzaaVar.zzjQ()) {
            int zzjR = zzaaVar.zzjR();
            this.zzLX = zzjR;
            this.zzMM = true;
            zzb("XML config - dispatch period (sec)", Integer.valueOf(zzjR));
        }
        if (zzaaVar.zzjS()) {
            boolean zzjT = zzaaVar.zzjT();
            this.zzIx = zzjT;
            this.zzMN = true;
            zzb("XML config - dry run", Boolean.valueOf(zzjT));
        }
    }

    @Override // com.google.android.gms.analytics.internal.zzd
    protected void zzhn() {
        zzkI();
    }

    public String zzjL() {
        zzia();
        return this.zzLU;
    }

    public String zzjN() {
        zzia();
        return this.zzLV;
    }

    public boolean zzjO() {
        zzia();
        return this.zzML;
    }

    public boolean zzjQ() {
        zzia();
        return this.zzMM;
    }

    public boolean zzjS() {
        zzia();
        return this.zzMN;
    }

    public boolean zzjT() {
        zzia();
        return this.zzIx;
    }

    public int zzkH() {
        zzia();
        return this.zzLX;
    }

    protected void zzkI() {
        ApplicationInfo applicationInfo;
        int i;
        zzaa zzab;
        Context context = getContext();
        try {
            applicationInfo = context.getPackageManager().getApplicationInfo(context.getPackageName(), 129);
        } catch (PackageManager.NameNotFoundException e) {
            zzd("PackageManager doesn't know about the app package", e);
            applicationInfo = null;
        }
        if (applicationInfo == null) {
            zzaW("Couldn't get ApplicationInfo to load global config");
            return;
        }
        Bundle bundle = applicationInfo.metaData;
        if (bundle == null || (i = bundle.getInt("com.google.android.gms.analytics.globalConfigResource")) <= 0 || (zzab = new zzz(zzhM()).zzab(i)) == null) {
            return;
        }
        zza(zzab);
    }
}
