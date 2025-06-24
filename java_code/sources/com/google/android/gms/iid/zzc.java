package com.google.android.gms.iid;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.ConditionVariable;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.Parcelable;
import android.os.Process;
import android.os.RemoteException;
import android.os.SystemClock;
import android.support.v7.media.MediaRouteProviderProtocol;
import android.text.TextUtils;
import android.util.Log;
import com.google.android.gms.gcm.GoogleCloudMessaging;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
/* loaded from: classes.dex */
public class zzc {
    static String zzaxd = null;
    static int zzaxe = 0;
    static int zzaxf = 0;
    static int zzaxg = 0;
    PendingIntent zzavT;
    Messenger zzavX;
    Map<String, Object> zzaxh = new HashMap();
    Messenger zzaxi;
    MessengerCompat zzaxj;
    long zzaxk;
    long zzaxl;
    int zzaxm;
    int zzaxn;
    long zzaxo;
    Context zzpH;

    public zzc(Context context) {
        this.zzpH = context;
    }

    static String zza(KeyPair keyPair, String... strArr) {
        try {
            byte[] bytes = TextUtils.join("\n", strArr).getBytes("UTF-8");
            try {
                PrivateKey privateKey = keyPair.getPrivate();
                Signature signature = Signature.getInstance(privateKey instanceof RSAPrivateKey ? "SHA256withRSA" : "SHA256withECDSA");
                signature.initSign(privateKey);
                signature.update(bytes);
                return InstanceID.zzm(signature.sign());
            } catch (GeneralSecurityException e) {
                Log.e("InstanceID/Rpc", "Unable to sign registration request", e);
                return null;
            }
        } catch (UnsupportedEncodingException e2) {
            Log.e("InstanceID/Rpc", "Unable to encode string", e2);
            return null;
        }
    }

    public static String zzaw(Context context) {
        if (zzaxd != null) {
            return zzaxd;
        }
        zzaxe = Process.myUid();
        PackageManager packageManager = context.getPackageManager();
        for (ResolveInfo resolveInfo : packageManager.queryIntentServices(new Intent("com.google.android.c2dm.intent.REGISTER"), 0)) {
            if (packageManager.checkPermission("com.google.android.c2dm.permission.RECEIVE", resolveInfo.serviceInfo.packageName) == 0) {
                try {
                    ApplicationInfo applicationInfo = packageManager.getApplicationInfo(resolveInfo.serviceInfo.packageName, 0);
                    Log.w("InstanceID/Rpc", "Found " + applicationInfo.uid);
                    zzaxf = applicationInfo.uid;
                    zzaxd = resolveInfo.serviceInfo.packageName;
                    return zzaxd;
                } catch (PackageManager.NameNotFoundException e) {
                }
            } else {
                Log.w("InstanceID/Rpc", "Possible malicious package " + resolveInfo.serviceInfo.packageName + " declares com.google.android.c2dm.intent.REGISTER without permission");
            }
        }
        Log.w("InstanceID/Rpc", "Failed to resolve REGISTER intent, falling back");
        try {
            ApplicationInfo applicationInfo2 = packageManager.getApplicationInfo("com.google.android.gms", 0);
            zzaxd = applicationInfo2.packageName;
            zzaxf = applicationInfo2.uid;
            return zzaxd;
        } catch (PackageManager.NameNotFoundException e2) {
            try {
                ApplicationInfo applicationInfo3 = packageManager.getApplicationInfo("com.google.android.gsf", 0);
                zzaxd = applicationInfo3.packageName;
                zzaxf = applicationInfo3.uid;
                return zzaxd;
            } catch (PackageManager.NameNotFoundException e3) {
                Log.w("InstanceID/Rpc", "Both Google Play Services and legacy GSF package are missing");
                return null;
            }
        }
    }

    private Intent zzb(Bundle bundle, KeyPair keyPair) throws IOException {
        Intent intent;
        ConditionVariable conditionVariable = new ConditionVariable();
        String zzuk = zzuk();
        synchronized (getClass()) {
            this.zzaxh.put(zzuk, conditionVariable);
        }
        zza(bundle, keyPair, zzuk);
        conditionVariable.block(30000L);
        synchronized (getClass()) {
            Object remove = this.zzaxh.remove(zzuk);
            if (!(remove instanceof Intent)) {
                if (remove instanceof String) {
                    throw new IOException((String) remove);
                }
                Log.w("InstanceID/Rpc", "No response " + remove);
                throw new IOException(InstanceID.ERROR_TIMEOUT);
            }
            intent = (Intent) remove;
        }
        return intent;
    }

    private void zzdd(String str) {
        if ("com.google.android.gsf".equals(zzaxd)) {
            this.zzaxm++;
            if (this.zzaxm >= 3) {
                if (this.zzaxm == 3) {
                    this.zzaxn = new Random().nextInt(1000) + 1000;
                }
                this.zzaxn *= 2;
                this.zzaxo = SystemClock.elapsedRealtime() + this.zzaxn;
                Log.w("InstanceID/Rpc", "Backoff due to " + str + " for " + this.zzaxn);
            }
        }
    }

    private void zze(Object obj, Object obj2) {
        if (obj instanceof ConditionVariable) {
            ((ConditionVariable) obj).open();
        }
        if (obj instanceof Messenger) {
            Messenger messenger = (Messenger) obj;
            Message obtain = Message.obtain();
            obtain.obj = obj2;
            try {
                messenger.send(obtain);
            } catch (RemoteException e) {
                Log.w("InstanceID/Rpc", "Failed to send response " + e);
            }
        }
    }

    private void zzi(String str, Object obj) {
        synchronized (getClass()) {
            Object obj2 = this.zzaxh.get(str);
            this.zzaxh.put(str, obj);
            zze(obj2, obj);
        }
    }

    public static synchronized String zzuk() {
        String num;
        synchronized (zzc.class) {
            int i = zzaxg;
            zzaxg = i + 1;
            num = Integer.toString(i);
        }
        return num;
    }

    private void zzx(Object obj) {
        synchronized (getClass()) {
            for (String str : this.zzaxh.keySet()) {
                Object obj2 = this.zzaxh.get(str);
                this.zzaxh.put(str, obj);
                zze(obj2, obj);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Intent zza(Bundle bundle, KeyPair keyPair) throws IOException {
        Intent zzb = zzb(bundle, keyPair);
        return (zzb == null || !zzb.hasExtra("google.messenger")) ? zzb : zzb(bundle, keyPair);
    }

    void zza(Bundle bundle, KeyPair keyPair, String str) throws IOException {
        long elapsedRealtime = SystemClock.elapsedRealtime();
        if (this.zzaxo != 0 && elapsedRealtime <= this.zzaxo) {
            Log.w("InstanceID/Rpc", "Backoff mode, next request attempt: " + (this.zzaxo - elapsedRealtime) + " interval: " + this.zzaxn);
            throw new IOException(InstanceID.ERROR_BACKOFF);
        }
        zzuj();
        if (zzaxd == null) {
            throw new IOException(InstanceID.ERROR_MISSING_INSTANCEID_SERVICE);
        }
        this.zzaxk = SystemClock.elapsedRealtime();
        Intent intent = new Intent("com.google.android.c2dm.intent.REGISTER");
        intent.setPackage(zzaxd);
        bundle.putString("gmsv", Integer.toString(GoogleCloudMessaging.zzat(this.zzpH)));
        bundle.putString("osv", Integer.toString(Build.VERSION.SDK_INT));
        bundle.putString("app_ver", Integer.toString(InstanceID.zzau(this.zzpH)));
        bundle.putString("cliv", "1");
        bundle.putString("appid", InstanceID.zza(keyPair));
        String zzm = InstanceID.zzm(keyPair.getPublic().getEncoded());
        bundle.putString("pub2", zzm);
        bundle.putString("sig", zza(keyPair, this.zzpH.getPackageName(), zzm));
        intent.putExtras(bundle);
        zzo(intent);
        zzb(intent, str);
    }

    protected void zzb(Intent intent, String str) {
        this.zzaxk = SystemClock.elapsedRealtime();
        intent.putExtra("kid", "|ID|" + str + "|");
        intent.putExtra("X-kid", "|ID|" + str + "|");
        boolean equals = "com.google.android.gsf".equals(zzaxd);
        String stringExtra = intent.getStringExtra("useGsf");
        if (stringExtra != null) {
            equals = "1".equals(stringExtra);
        }
        if (Log.isLoggable("InstanceID/Rpc", 3)) {
            Log.d("InstanceID/Rpc", "Sending " + intent.getExtras());
        }
        if (this.zzaxi != null) {
            intent.putExtra("google.messenger", this.zzavX);
            Message obtain = Message.obtain();
            obtain.obj = intent;
            try {
                this.zzaxi.send(obtain);
                return;
            } catch (RemoteException e) {
                if (Log.isLoggable("InstanceID/Rpc", 3)) {
                    Log.d("InstanceID/Rpc", "Messenger failed, fallback to startService");
                }
            }
        }
        if (equals) {
            Intent intent2 = new Intent("com.google.android.gms.iid.InstanceID");
            intent2.setPackage(this.zzpH.getPackageName());
            intent2.putExtra("GSF", intent);
            this.zzpH.startService(intent2);
            return;
        }
        intent.putExtra("google.messenger", this.zzavX);
        intent.putExtra("messenger2", "1");
        if (this.zzaxj != null) {
            Message obtain2 = Message.obtain();
            obtain2.obj = intent;
            try {
                this.zzaxj.send(obtain2);
                return;
            } catch (RemoteException e2) {
                if (Log.isLoggable("InstanceID/Rpc", 3)) {
                    Log.d("InstanceID/Rpc", "Messenger failed, fallback to startService");
                }
            }
        }
        this.zzpH.startService(intent);
    }

    public void zze(Message message) {
        if (message == null) {
            return;
        }
        if (!(message.obj instanceof Intent)) {
            Log.w("InstanceID/Rpc", "Dropping invalid message");
            return;
        }
        Intent intent = (Intent) message.obj;
        intent.setExtrasClassLoader(MessengerCompat.class.getClassLoader());
        if (intent.hasExtra("google.messenger")) {
            Parcelable parcelableExtra = intent.getParcelableExtra("google.messenger");
            if (parcelableExtra instanceof MessengerCompat) {
                this.zzaxj = (MessengerCompat) parcelableExtra;
            }
            if (parcelableExtra instanceof Messenger) {
                this.zzaxi = (Messenger) parcelableExtra;
            }
        }
        zzr((Intent) message.obj);
    }

    synchronized void zzo(Intent intent) {
        if (this.zzavT == null) {
            Intent intent2 = new Intent();
            intent2.setPackage("com.google.example.invalidpackage");
            this.zzavT = PendingIntent.getBroadcast(this.zzpH, 0, intent2, 0);
        }
        intent.putExtra("app", this.zzavT);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String zzp(Intent intent) throws IOException {
        if (intent == null) {
            throw new IOException("SERVICE_NOT_AVAILABLE");
        }
        String stringExtra = intent.getStringExtra("registration_id");
        if (stringExtra == null) {
            stringExtra = intent.getStringExtra("unregistered");
        }
        intent.getLongExtra("Retry-After", 0L);
        if (stringExtra != null) {
        }
        if (stringExtra == null) {
            String stringExtra2 = intent.getStringExtra(MediaRouteProviderProtocol.SERVICE_DATA_ERROR);
            if (stringExtra2 != null) {
                throw new IOException(stringExtra2);
            }
            Log.w("InstanceID/Rpc", "Unexpected response from GCM " + intent.getExtras(), new Throwable());
            throw new IOException("SERVICE_NOT_AVAILABLE");
        }
        return stringExtra;
    }

    void zzq(Intent intent) {
        String stringExtra = intent.getStringExtra(MediaRouteProviderProtocol.SERVICE_DATA_ERROR);
        if (stringExtra == null) {
            Log.w("InstanceID/Rpc", "Unexpected response, no error or registration id " + intent.getExtras());
            return;
        }
        if (Log.isLoggable("InstanceID/Rpc", 3)) {
            Log.d("InstanceID/Rpc", "Received InstanceID error " + stringExtra);
        }
        String str = null;
        if (stringExtra.startsWith("|")) {
            String[] split = stringExtra.split("\\|");
            if (!"ID".equals(split[1])) {
                Log.w("InstanceID/Rpc", "Unexpected structured response " + stringExtra);
            }
            if (split.length > 2) {
                str = split[2];
                stringExtra = split[3];
                if (stringExtra.startsWith(":")) {
                    stringExtra = stringExtra.substring(1);
                }
            } else {
                stringExtra = "UNKNOWN";
            }
            intent.putExtra(MediaRouteProviderProtocol.SERVICE_DATA_ERROR, stringExtra);
        }
        if (str == null) {
            zzx(stringExtra);
        } else {
            zzi(str, stringExtra);
        }
        long longExtra = intent.getLongExtra("Retry-After", 0L);
        if (longExtra > 0) {
            this.zzaxl = SystemClock.elapsedRealtime();
            this.zzaxn = ((int) longExtra) * 1000;
            this.zzaxo = SystemClock.elapsedRealtime() + this.zzaxn;
            Log.w("InstanceID/Rpc", "Explicit request from server to backoff: " + this.zzaxn);
        } else if ("SERVICE_NOT_AVAILABLE".equals(stringExtra) || "AUTHENTICATION_FAILED".equals(stringExtra)) {
            zzdd(stringExtra);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zzr(Intent intent) {
        if (intent == null) {
            if (Log.isLoggable("InstanceID/Rpc", 3)) {
                Log.d("InstanceID/Rpc", "Unexpected response: null");
                return;
            }
            return;
        }
        String action = intent.getAction();
        if (!"com.google.android.c2dm.intent.REGISTRATION".equals(action) && !"com.google.android.gms.iid.InstanceID".equals(action)) {
            if (Log.isLoggable("InstanceID/Rpc", 3)) {
                Log.d("InstanceID/Rpc", "Unexpected response " + intent.getAction());
                return;
            }
            return;
        }
        String stringExtra = intent.getStringExtra("registration_id");
        String stringExtra2 = stringExtra == null ? intent.getStringExtra("unregistered") : stringExtra;
        if (stringExtra2 == null) {
            zzq(intent);
            return;
        }
        this.zzaxk = SystemClock.elapsedRealtime();
        this.zzaxo = 0L;
        this.zzaxm = 0;
        this.zzaxn = 0;
        if (Log.isLoggable("InstanceID/Rpc", 3)) {
            Log.d("InstanceID/Rpc", "AppIDResponse: " + stringExtra2 + " " + intent.getExtras());
        }
        String str = null;
        if (stringExtra2.startsWith("|")) {
            String[] split = stringExtra2.split("\\|");
            if (!"ID".equals(split[1])) {
                Log.w("InstanceID/Rpc", "Unexpected structured response " + stringExtra2);
            }
            String str2 = split[2];
            if (split.length > 4) {
                if ("SYNC".equals(split[3])) {
                    InstanceIDListenerService.zzav(this.zzpH);
                } else if ("RST".equals(split[3])) {
                    InstanceIDListenerService.zza(this.zzpH, InstanceID.getInstance(this.zzpH).zzug());
                    intent.removeExtra("registration_id");
                    zzi(str2, intent);
                    return;
                }
            }
            String str3 = split[split.length - 1];
            if (str3.startsWith(":")) {
                str3 = str3.substring(1);
            }
            intent.putExtra("registration_id", str3);
            str = str2;
        }
        if (str == null) {
            zzx(intent);
        } else {
            zzi(str, intent);
        }
    }

    void zzuj() {
        if (this.zzavX != null) {
            return;
        }
        zzaw(this.zzpH);
        this.zzavX = new Messenger(new Handler(Looper.getMainLooper()) { // from class: com.google.android.gms.iid.zzc.1
            @Override // android.os.Handler
            public void handleMessage(Message msg) {
                zzc.this.zze(msg);
            }
        });
    }
}
