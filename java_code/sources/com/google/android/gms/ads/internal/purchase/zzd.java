package com.google.android.gms.ads.internal.purchase;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.SystemClock;
import com.google.android.gms.ads.internal.zzo;
import com.google.android.gms.internal.zzfe;
import com.google.android.gms.internal.zzgd;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
@zzgd
/* loaded from: classes.dex */
public class zzd extends zzfe.zza {
    private Context mContext;
    private String zzAK;
    private ArrayList<String> zzAL;
    private String zzqr;

    public zzd(String str, ArrayList<String> arrayList, Context context, String str2) {
        this.zzAK = str;
        this.zzAL = arrayList;
        this.zzqr = str2;
        this.mContext = context;
    }

    @Override // com.google.android.gms.internal.zzfe
    public String getProductId() {
        return this.zzAK;
    }

    @Override // com.google.android.gms.internal.zzfe
    public void recordPlayBillingResolution(int billingResponseCode) {
        if (billingResponseCode == 0) {
            zzff();
        }
        HashMap<String, String> hashMap = new HashMap<>();
        hashMap.put("google_play_status", String.valueOf(billingResponseCode));
        hashMap.put("sku", this.zzAK);
        hashMap.put("status", String.valueOf(zzy(billingResponseCode)));
        LinkedList linkedList = new LinkedList();
        Iterator<String> it = this.zzAL.iterator();
        while (it.hasNext()) {
            linkedList.add(zza(it.next(), hashMap));
        }
        zzo.zzbv().zza(this.mContext, this.zzqr, linkedList);
    }

    @Override // com.google.android.gms.internal.zzfe
    public void recordResolution(int resolution) {
        if (resolution == 1) {
            zzff();
        }
        HashMap<String, String> hashMap = new HashMap<>();
        hashMap.put("status", String.valueOf(resolution));
        hashMap.put("sku", this.zzAK);
        LinkedList linkedList = new LinkedList();
        Iterator<String> it = this.zzAL.iterator();
        while (it.hasNext()) {
            linkedList.add(zza(it.next(), hashMap));
        }
        zzo.zzbv().zza(this.mContext, this.zzqr, linkedList);
    }

    protected String zza(String str, HashMap<String, String> hashMap) {
        String str2;
        String packageName = this.mContext.getPackageName();
        try {
            str2 = this.mContext.getPackageManager().getPackageInfo(packageName, 0).versionName;
        } catch (PackageManager.NameNotFoundException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Error to retrieve app version", e);
            str2 = "";
        }
        long elapsedRealtime = SystemClock.elapsedRealtime() - zzo.zzby().zzfX().zzgg();
        for (String str3 : hashMap.keySet()) {
            str = str.replaceAll(String.format("(?<!@)((?:@@)*)@%s(?<!@)((?:@@)*)@", str3), String.format("$1%s$2", hashMap.get(str3)));
        }
        return str.replaceAll(String.format("(?<!@)((?:@@)*)@%s(?<!@)((?:@@)*)@", "sessionid"), String.format("$1%s$2", zzo.zzby().getSessionId())).replaceAll(String.format("(?<!@)((?:@@)*)@%s(?<!@)((?:@@)*)@", "appid"), String.format("$1%s$2", packageName)).replaceAll(String.format("(?<!@)((?:@@)*)@%s(?<!@)((?:@@)*)@", "osversion"), String.format("$1%s$2", String.valueOf(Build.VERSION.SDK_INT))).replaceAll(String.format("(?<!@)((?:@@)*)@%s(?<!@)((?:@@)*)@", "sdkversion"), String.format("$1%s$2", this.zzqr)).replaceAll(String.format("(?<!@)((?:@@)*)@%s(?<!@)((?:@@)*)@", "appversion"), String.format("$1%s$2", str2)).replaceAll(String.format("(?<!@)((?:@@)*)@%s(?<!@)((?:@@)*)@", "timestamp"), String.format("$1%s$2", String.valueOf(elapsedRealtime))).replaceAll(String.format("(?<!@)((?:@@)*)@%s(?<!@)((?:@@)*)@", "[^@]+"), String.format("$1%s$2", "")).replaceAll("@@", "@");
    }

    void zzff() {
        try {
            this.mContext.getClassLoader().loadClass("com.google.ads.conversiontracking.IAPConversionReporter").getDeclaredMethod("reportWithProductId", Context.class, String.class, String.class, Boolean.TYPE).invoke(null, this.mContext, this.zzAK, "", true);
        } catch (ClassNotFoundException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Google Conversion Tracking SDK 1.2.0 or above is required to report a conversion.");
        } catch (NoSuchMethodException e2) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Google Conversion Tracking SDK 1.2.0 or above is required to report a conversion.");
        } catch (Exception e3) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Fail to report a conversion.", e3);
        }
    }

    protected int zzy(int i) {
        if (i == 0) {
            return 1;
        }
        if (i == 1) {
            return 2;
        }
        return i == 4 ? 3 : 0;
    }
}
