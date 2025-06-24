package com.google.android.gms.gcm;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.graphics.Color;
import android.media.RingtoneManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.Log;
import com.google.android.gms.drive.DriveFile;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zza {
    static zza zzavF;
    private Context mContext;

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: com.google.android.gms.gcm.zza$zza  reason: collision with other inner class name */
    /* loaded from: classes.dex */
    public class C0067zza extends IllegalArgumentException {
        private C0067zza(String str) {
            super(str);
        }
    }

    private zza(Context context) {
        this.mContext = context.getApplicationContext();
    }

    private void zza(String str, Notification notification) {
        if (Log.isLoggable("GcmNotification", 3)) {
            Log.d("GcmNotification", "Showing notification");
        }
        NotificationManager notificationManager = (NotificationManager) this.mContext.getSystemService("notification");
        if (TextUtils.isEmpty(str)) {
            str = "GCM-Notification:" + SystemClock.uptimeMillis();
        }
        notificationManager.notify(str, 0, notification);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static synchronized zza zzar(Context context) {
        zza zzaVar;
        synchronized (zza.class) {
            if (zzavF == null) {
                zzavF = new zza(context);
            }
            zzaVar = zzavF;
        }
        return zzaVar;
    }

    static String zzb(Bundle bundle, String str) {
        String string = bundle.getString(str);
        return string == null ? bundle.getString(str.replace("gcm.n.", "gcm.notification.")) : string;
    }

    private int zzda(String str) {
        if (TextUtils.isEmpty(str)) {
            throw new C0067zza("Missing icon");
        }
        Resources resources = this.mContext.getResources();
        int identifier = resources.getIdentifier(str, "drawable", this.mContext.getPackageName());
        if (identifier == 0 && (identifier = resources.getIdentifier(str, "mipmap", this.mContext.getPackageName())) == 0) {
            throw new C0067zza("Icon resource not found: " + str);
        }
        return identifier;
    }

    private Uri zzdb(String str) {
        if (TextUtils.isEmpty(str)) {
            return null;
        }
        if ("default".equals(str)) {
            return RingtoneManager.getDefaultUri(2);
        }
        throw new C0067zza("Invalid sound: " + str);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean zzt(Bundle bundle) {
        return zzb(bundle, "gcm.n.title") != null;
    }

    private Notification zzv(Bundle bundle) {
        String zzb = zzb(bundle, "gcm.n.title");
        if (TextUtils.isEmpty(zzb)) {
            throw new C0067zza("Missing title");
        }
        String zzb2 = zzb(bundle, "gcm.n.body");
        int zzda = zzda(zzb(bundle, "gcm.n.icon"));
        Uri zzdb = zzdb(zzb(bundle, "gcm.n.sound"));
        PendingIntent zzw = zzw(bundle);
        if (Build.VERSION.SDK_INT >= 11) {
            Notification.Builder contentText = new Notification.Builder(this.mContext).setAutoCancel(true).setSmallIcon(zzda).setContentTitle(zzb).setContentText(zzb2);
            if (Build.VERSION.SDK_INT >= 21) {
                String zzb3 = zzb(bundle, "gcm.n.color");
                if (!TextUtils.isEmpty(zzb3)) {
                    contentText.setColor(Color.parseColor(zzb3));
                }
            }
            if (zzdb != null) {
                contentText.setSound(zzdb);
            }
            if (zzw != null) {
                contentText.setContentIntent(zzw);
            }
            return Build.VERSION.SDK_INT >= 16 ? contentText.build() : contentText.getNotification();
        }
        Notification notification = new Notification();
        notification.flags |= 16;
        notification.icon = zzda;
        if (zzdb != null) {
            notification.sound = zzdb;
        }
        if (zzw == null) {
            Intent intent = new Intent();
            intent.setPackage("com.google.example.invalidpackage");
            zzw = PendingIntent.getBroadcast(this.mContext, 0, intent, 0);
        }
        notification.setLatestEventInfo(this.mContext, zzb, zzb2, zzw);
        return notification;
    }

    private PendingIntent zzw(Bundle bundle) {
        String zzb = zzb(bundle, "gcm.n.click_action");
        if (TextUtils.isEmpty(zzb)) {
            return null;
        }
        Intent intent = new Intent(zzb);
        intent.setPackage(this.mContext.getPackageName());
        intent.setFlags(DriveFile.MODE_READ_ONLY);
        intent.putExtras(bundle);
        for (String str : bundle.keySet()) {
            if (str.startsWith("gcm.n.") || str.startsWith("gcm.notification.")) {
                intent.removeExtra(str);
            }
        }
        return PendingIntent.getActivity(this.mContext, 0, intent, 1073741824);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean zzu(Bundle bundle) {
        try {
            zza(zzb(bundle, "gcm.n.tag"), zzv(bundle));
            return true;
        } catch (C0067zza e) {
            Log.w("GcmNotification", "Failed to show notification: " + e.getMessage());
            return false;
        }
    }
}
