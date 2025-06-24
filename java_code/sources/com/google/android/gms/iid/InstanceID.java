package com.google.android.gms.iid;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Looper;
import android.util.Base64;
import android.util.Log;
import java.io.IOException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
public class InstanceID {
    public static final String ERROR_BACKOFF = "RETRY_LATER";
    public static final String ERROR_MAIN_THREAD = "MAIN_THREAD";
    public static final String ERROR_MISSING_INSTANCEID_SERVICE = "MISSING_INSTANCEID_SERVICE";
    public static final String ERROR_SERVICE_NOT_AVAILABLE = "SERVICE_NOT_AVAILABLE";
    public static final String ERROR_TIMEOUT = "TIMEOUT";
    static Map<String, InstanceID> zzawN = new HashMap();
    private static zzd zzawO;
    private static zzc zzawP;
    static String zzawT;
    Context mContext;
    KeyPair zzawQ;
    String zzawR;
    long zzawS;

    protected InstanceID(Context context, String subtype, Bundle options) {
        this.zzawR = "";
        this.mContext = context.getApplicationContext();
        this.zzawR = subtype;
    }

    public static InstanceID getInstance(Context context) {
        return zza(context, null);
    }

    public static synchronized InstanceID zza(Context context, Bundle bundle) {
        InstanceID instanceID;
        synchronized (InstanceID.class) {
            String string = bundle == null ? "" : bundle.getString("subtype");
            String str = string == null ? "" : string;
            Context applicationContext = context.getApplicationContext();
            if (zzawO == null) {
                zzawO = new zzd(applicationContext);
                zzawP = new zzc(applicationContext);
            }
            zzawT = Integer.toString(zzau(applicationContext));
            instanceID = zzawN.get(str);
            if (instanceID == null) {
                instanceID = new InstanceID(applicationContext, str, bundle);
                zzawN.put(str, instanceID);
            }
        }
        return instanceID;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String zza(KeyPair keyPair) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA1").digest(keyPair.getPublic().getEncoded());
            digest[0] = (byte) (((digest[0] & 15) + 112) & 255);
            return Base64.encodeToString(digest, 0, 8, 11);
        } catch (NoSuchAlgorithmException e) {
            Log.w("InstanceID", "Unexpected error, device missing required alghorithms");
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int zzau(Context context) {
        try {
            return context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionCode;
        } catch (PackageManager.NameNotFoundException e) {
            Log.w("InstanceID", "Never happens: can't find own package " + e);
            return 0;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String zzm(byte[] bArr) {
        return Base64.encodeToString(bArr, 11);
    }

    public void deleteInstanceID() throws IOException {
        zzb("*", "*", null);
        zzuf();
    }

    public void deleteToken(String authorizedEntity, String scope) throws IOException {
        zzb(authorizedEntity, scope, null);
    }

    public long getCreationTime() {
        String str;
        if (this.zzawS == 0 && (str = zzawO.get(this.zzawR, "cre")) != null) {
            this.zzawS = Long.parseLong(str);
        }
        return this.zzawS;
    }

    public String getId() {
        return zza(zzue());
    }

    public String getToken(String authorizedEntity, String scope) throws IOException {
        return getToken(authorizedEntity, scope, null);
    }

    public String getToken(String authorizedEntity, String scope, Bundle extras) throws IOException {
        if (Looper.getMainLooper() == Looper.myLooper()) {
            throw new IOException("MAIN_THREAD");
        }
        String zzg = zzui() ? null : zzawO.zzg(this.zzawR, authorizedEntity, scope);
        if (zzg == null) {
            if (extras == null) {
                extras = new Bundle();
            }
            zzg = zzc(authorizedEntity, scope, extras);
            if (zzg != null) {
                zzawO.zza(this.zzawR, authorizedEntity, scope, zzg, zzawT);
            }
        }
        return zzg;
    }

    public void zzb(String str, String str2, Bundle bundle) throws IOException {
        if (Looper.getMainLooper() == Looper.myLooper()) {
            throw new IOException("MAIN_THREAD");
        }
        zzawO.zzh(this.zzawR, str, str2);
        if (bundle == null) {
            bundle = new Bundle();
        }
        bundle.putString("sender", str);
        if (str2 != null) {
            bundle.putString("scope", str2);
        }
        bundle.putString("subscription", str);
        bundle.putString("delete", "1");
        bundle.putString("X-delete", "1");
        bundle.putString("subtype", "".equals(this.zzawR) ? str : this.zzawR);
        if (!"".equals(this.zzawR)) {
            str = this.zzawR;
        }
        bundle.putString("X-subtype", str);
        zzawP.zzp(zzawP.zza(bundle, zzue()));
    }

    public String zzc(String str, String str2, Bundle bundle) throws IOException {
        if (str2 != null) {
            bundle.putString("scope", str2);
        }
        bundle.putString("sender", str);
        String str3 = "".equals(this.zzawR) ? str : this.zzawR;
        if (!bundle.containsKey("legacy.register")) {
            bundle.putString("subscription", str);
            bundle.putString("subtype", str3);
            bundle.putString("X-subscription", str);
            bundle.putString("X-subtype", str3);
        }
        return zzawP.zzp(zzawP.zza(bundle, zzue()));
    }

    KeyPair zzue() {
        if (this.zzawQ == null) {
            this.zzawQ = zzawO.zzdg(this.zzawR);
        }
        if (this.zzawQ == null) {
            this.zzawS = System.currentTimeMillis();
            this.zzawQ = zzawO.zze(this.zzawR, this.zzawS);
        }
        return this.zzawQ;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zzuf() {
        this.zzawS = 0L;
        zzawO.zzdh(this.zzawR);
        this.zzawQ = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzd zzug() {
        return zzawO;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzc zzuh() {
        return zzawP;
    }

    boolean zzui() {
        String str;
        String str2 = zzawO.get("appVersion");
        if (str2 == null || !str2.equals(zzawT) || (str = zzawO.get("lastToken")) == null) {
            return true;
        }
        return (System.currentTimeMillis() / 1000) - Long.valueOf(Long.parseLong(str)).longValue() > 604800;
    }
}
