package com.google.android.gms.common;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.AppOpsManager;
import android.app.Dialog;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentActivity;
import android.support.v4.app.NotificationCompatExtras;
import android.text.TextUtils;
import android.util.Log;
import android.util.TypedValue;
import com.google.android.gms.R;
import com.google.android.gms.common.internal.zzf;
import com.google.android.gms.common.internal.zzg;
import com.google.android.gms.common.internal.zzm;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.common.zzc;
import com.google.android.gms.drive.DriveFile;
import com.google.android.gms.internal.zzkz;
import com.google.android.gms.internal.zzlk;
import java.io.InputStream;
import java.util.NoSuchElementException;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicBoolean;
/* loaded from: classes.dex */
public final class GooglePlayServicesUtil {
    public static final String GMS_ERROR_DIALOG = "GooglePlayServicesErrorDialog";
    @Deprecated
    public static final String GOOGLE_PLAY_SERVICES_PACKAGE = "com.google.android.gms";
    public static final String GOOGLE_PLAY_STORE_PACKAGE = "com.android.vending";
    @Deprecated
    public static final int GOOGLE_PLAY_SERVICES_VERSION_CODE = zzml();
    public static boolean zzVS = false;
    public static boolean zzVT = false;
    private static int zzVU = -1;
    private static final Object zzoW = new Object();
    private static String zzVV = null;
    private static Integer zzVW = null;
    static final AtomicBoolean zzVX = new AtomicBoolean();

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class zza extends Handler {
        private final Context zzqw;

        zza(Context context) {
            super(Looper.myLooper() == null ? Looper.getMainLooper() : Looper.myLooper());
            this.zzqw = context.getApplicationContext();
        }

        @Override // android.os.Handler
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case 1:
                    int isGooglePlayServicesAvailable = GooglePlayServicesUtil.isGooglePlayServicesAvailable(this.zzqw);
                    if (GooglePlayServicesUtil.isUserRecoverableError(isGooglePlayServicesAvailable)) {
                        GooglePlayServicesUtil.zza(isGooglePlayServicesAvailable, this.zzqw);
                        return;
                    }
                    return;
                default:
                    Log.w("GooglePlayServicesUtil", "Don't know how to handle this message: " + msg.what);
                    return;
            }
        }
    }

    private GooglePlayServicesUtil() {
    }

    @Deprecated
    public static Dialog getErrorDialog(int errorCode, Activity activity, int requestCode) {
        return getErrorDialog(errorCode, activity, requestCode, null);
    }

    @Deprecated
    public static Dialog getErrorDialog(int errorCode, Activity activity, int requestCode, DialogInterface.OnCancelListener cancelListener) {
        return zza(errorCode, activity, null, requestCode, cancelListener);
    }

    @Deprecated
    public static PendingIntent getErrorPendingIntent(int errorCode, Context context, int requestCode) {
        Intent zzaT = zzaT(errorCode);
        if (zzaT == null) {
            return null;
        }
        return PendingIntent.getActivity(context, requestCode, zzaT, DriveFile.MODE_READ_ONLY);
    }

    @Deprecated
    public static String getErrorString(int errorCode) {
        return ConnectionResult.getStatusString(errorCode);
    }

    @Deprecated
    public static String getOpenSourceSoftwareLicenseInfo(Context context) {
        try {
            InputStream openInputStream = context.getContentResolver().openInputStream(new Uri.Builder().scheme("android.resource").authority("com.google.android.gms").appendPath("raw").appendPath("oss_notice").build());
            try {
                String next = new Scanner(openInputStream).useDelimiter("\\A").next();
                if (openInputStream != null) {
                    openInputStream.close();
                    return next;
                }
                return next;
            } catch (NoSuchElementException e) {
                if (openInputStream != null) {
                    openInputStream.close();
                }
                return null;
            } catch (Throwable th) {
                if (openInputStream != null) {
                    openInputStream.close();
                }
                throw th;
            }
        } catch (Exception e2) {
            return null;
        }
    }

    public static Context getRemoteContext(Context context) {
        try {
            return context.createPackageContext("com.google.android.gms", 3);
        } catch (PackageManager.NameNotFoundException e) {
            return null;
        }
    }

    public static Resources getRemoteResource(Context context) {
        try {
            return context.getPackageManager().getResourcesForApplication("com.google.android.gms");
        } catch (PackageManager.NameNotFoundException e) {
            return null;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r3v4, types: [java.lang.String] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:31:0x0091 -> B:39:0x00ba). Please submit an issue!!! */
    @Deprecated
    public static int isGooglePlayServicesAvailable(Context context) {
        PackageManager packageManager;
        int i = 1;
        String str = 0;
        r1 = 0;
        r1 = 0;
        str = 0;
        String str2 = 0;
        int i2 = 9;
        if (com.google.android.gms.common.internal.zzd.zzZR) {
            return 0;
        }
        PackageManager packageManager2 = context.getPackageManager();
        try {
            context.getResources().getString(R.string.common_google_play_services_unknown_issue);
        } catch (Throwable th) {
            Log.e("GooglePlayServicesUtil", "The Google Play services resources were not found. Check your project configuration to ensure that the resources are included.");
        }
        if (!"com.google.android.gms".equals(context.getPackageName())) {
            zzaa(context);
        }
        try {
            PackageInfo packageInfo = packageManager2.getPackageInfo("com.google.android.gms", 64);
            zzd zzmn = zzd.zzmn();
            if (!zzkz.zzbP(packageInfo.versionCode) && !zzkz.zzai(context)) {
                try {
                    zzc.zza zza2 = zzmn.zza(packageManager2.getPackageInfo(GOOGLE_PLAY_STORE_PACKAGE, 64), zzc.zzbk.zzVR);
                    if (zza2 == null) {
                        Log.w("GooglePlayServicesUtil", "Google Play Store signature invalid.");
                        packageManager2 = packageManager2;
                        zzmn = zzmn;
                    } else {
                        packageManager = packageManager2;
                        if (zzmn.zza(packageInfo, zza2) == null) {
                            Log.w("GooglePlayServicesUtil", "Google Play services signature invalid.");
                            packageManager2 = packageManager2;
                            zzmn = zzmn;
                        }
                    }
                } catch (PackageManager.NameNotFoundException e) {
                    if (!zzh(context, GOOGLE_PLAY_STORE_PACKAGE)) {
                        Log.w("GooglePlayServicesUtil", "Google Play Store is neither installed nor updating.");
                        return i2;
                    }
                    Log.w("GooglePlayServicesUtil", "Google Play Store is updating.");
                    str = str2;
                    packageManager = packageManager2;
                    if (zzmn.zza(packageInfo, zzc.zzbk.zzVR) == null) {
                        Log.w("GooglePlayServicesUtil", "Google Play services signature invalid.");
                        return i2;
                    }
                }
                return i2;
            }
            packageManager = packageManager2;
            if (zzmn.zza(packageInfo, zzc.zzbk.zzVR) == null) {
                Log.w("GooglePlayServicesUtil", "Google Play services signature invalid.");
                return 9;
            }
            int zzbN = zzkz.zzbN(GOOGLE_PLAY_SERVICES_VERSION_CODE);
            int zzbN2 = zzkz.zzbN(packageInfo.versionCode);
            if (zzbN2 < zzbN) {
                StringBuilder append = new StringBuilder().append("Google Play services out of date.  Requires ").append(GOOGLE_PLAY_SERVICES_VERSION_CODE).append(" but found ");
                i = packageInfo.versionCode;
                String sb = append.append(i).toString();
                Log.w("GooglePlayServicesUtil", sb);
                i2 = 2;
                str2 = sb;
                packageManager2 = packageManager;
                zzmn = zzbN2;
            } else {
                ApplicationInfo applicationInfo = packageInfo.applicationInfo;
                if (applicationInfo == null) {
                    try {
                        packageInfo = null;
                        applicationInfo = packageManager.getApplicationInfo("com.google.android.gms", 0);
                    } catch (PackageManager.NameNotFoundException e2) {
                        Log.wtf("GooglePlayServicesUtil", "Google Play services missing when getting application info.");
                        e2.printStackTrace();
                        i2 = i;
                        str2 = "GooglePlayServicesUtil";
                        packageManager2 = "Google Play services missing when getting application info.";
                        zzmn = zzbN2;
                    }
                }
                if (applicationInfo.enabled) {
                    i2 = str;
                    str2 = str;
                    packageManager2 = packageManager;
                    zzmn = zzbN2;
                } else {
                    i2 = 3;
                    str2 = str;
                    packageManager2 = packageManager;
                    zzmn = zzbN2;
                }
            }
            return i2;
        } catch (PackageManager.NameNotFoundException e3) {
            Log.w("GooglePlayServicesUtil", "Google Play services is missing.");
            return 1;
        }
    }

    @Deprecated
    public static boolean isUserRecoverableError(int errorCode) {
        switch (errorCode) {
            case 1:
            case 2:
            case 3:
            case 9:
                return true;
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            default:
                return false;
        }
    }

    @Deprecated
    public static boolean showErrorDialogFragment(int errorCode, Activity activity, int requestCode) {
        return showErrorDialogFragment(errorCode, activity, requestCode, null);
    }

    @Deprecated
    public static boolean showErrorDialogFragment(int errorCode, Activity activity, int requestCode, DialogInterface.OnCancelListener cancelListener) {
        return showErrorDialogFragment(errorCode, activity, null, requestCode, cancelListener);
    }

    public static boolean showErrorDialogFragment(int errorCode, Activity activity, Fragment fragment, int requestCode, DialogInterface.OnCancelListener cancelListener) {
        boolean z = false;
        Dialog zza2 = zza(errorCode, activity, fragment, requestCode, cancelListener);
        if (zza2 == null) {
            return false;
        }
        try {
            z = activity instanceof FragmentActivity;
        } catch (NoClassDefFoundError e) {
        }
        if (z) {
            SupportErrorDialogFragment.newInstance(zza2, cancelListener).show(((FragmentActivity) activity).getSupportFragmentManager(), GMS_ERROR_DIALOG);
        } else if (!zzlk.zzoR()) {
            throw new RuntimeException("This Activity does not support Fragments.");
        } else {
            ErrorDialogFragment.newInstance(zza2, cancelListener).show(activity.getFragmentManager(), GMS_ERROR_DIALOG);
        }
        return true;
    }

    @Deprecated
    public static void showErrorNotification(int errorCode, Context context) {
        if (zzkz.zzai(context) && errorCode == 2) {
            errorCode = 42;
        }
        if (zze(context, errorCode) || zzf(context, errorCode)) {
            zzab(context);
        } else {
            zza(errorCode, context);
        }
    }

    @Deprecated
    public static void zzY(Context context) throws GooglePlayServicesRepairableException, GooglePlayServicesNotAvailableException {
        int isGooglePlayServicesAvailable = isGooglePlayServicesAvailable(context);
        if (isGooglePlayServicesAvailable != 0) {
            Intent zzaT = zzaT(isGooglePlayServicesAvailable);
            Log.e("GooglePlayServicesUtil", "GooglePlayServices not available due to error " + isGooglePlayServicesAvailable);
            if (zzaT != null) {
                throw new GooglePlayServicesRepairableException(isGooglePlayServicesAvailable, "Google Play Services not available", zzaT);
            }
            throw new GooglePlayServicesNotAvailableException(isGooglePlayServicesAvailable);
        }
    }

    private static Dialog zza(int i, Activity activity, Fragment fragment, int i2, DialogInterface.OnCancelListener onCancelListener) {
        AlertDialog.Builder builder = null;
        if (i == 0) {
            return null;
        }
        if (zzkz.zzai(activity) && i == 2) {
            i = 42;
        }
        if (zzlk.zzoU()) {
            TypedValue typedValue = new TypedValue();
            activity.getTheme().resolveAttribute(16843529, typedValue, true);
            if ("Theme.Dialog.Alert".equals(activity.getResources().getResourceEntryName(typedValue.resourceId))) {
                builder = new AlertDialog.Builder(activity, 5);
            }
        }
        if (builder == null) {
            builder = new AlertDialog.Builder(activity);
        }
        builder.setMessage(zzf.zzb(activity, i, zzad(activity)));
        if (onCancelListener != null) {
            builder.setOnCancelListener(onCancelListener);
        }
        Intent zzaT = zzaT(i);
        zzg zzgVar = fragment == null ? new zzg(activity, zzaT, i2) : new zzg(fragment, zzaT, i2);
        String zzh = zzf.zzh(activity, i);
        if (zzh != null) {
            builder.setPositiveButton(zzh, zzgVar);
        }
        String zzg = zzf.zzg(activity, i);
        if (zzg != null) {
            builder.setTitle(zzg);
        }
        return builder.create();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void zza(int i, Context context) {
        zza(i, context, (String) null);
    }

    private static void zza(int i, Context context, String str) {
        Notification notification;
        Notification notification2;
        int i2;
        Resources resources = context.getResources();
        String zzad = zzad(context);
        String zzi = zzf.zzi(context, i);
        if (zzi == null) {
            zzi = resources.getString(R.string.common_google_play_services_notification_ticker);
        }
        String zzc = zzf.zzc(context, i, zzad);
        PendingIntent errorPendingIntent = getErrorPendingIntent(i, context, 0);
        if (zzkz.zzai(context)) {
            zzu.zzU(zzlk.zzoV());
            notification = new Notification.Builder(context).setSmallIcon(R.drawable.common_ic_googleplayservices).setPriority(2).setAutoCancel(true).setStyle(new Notification.BigTextStyle().bigText(zzi + " " + zzc)).addAction(R.drawable.common_full_open_on_phone, resources.getString(R.string.common_open_on_phone), errorPendingIntent).build();
        } else {
            String string = resources.getString(R.string.common_google_play_services_notification_ticker);
            if (zzlk.zzoR()) {
                Notification.Builder autoCancel = new Notification.Builder(context).setSmallIcon(17301642).setContentTitle(zzi).setContentText(zzc).setContentIntent(errorPendingIntent).setTicker(string).setAutoCancel(true);
                if (zzlk.zzoY()) {
                    autoCancel.setLocalOnly(true);
                }
                if (zzlk.zzoV()) {
                    autoCancel.setStyle(new Notification.BigTextStyle().bigText(zzc));
                    notification2 = autoCancel.build();
                } else {
                    notification2 = autoCancel.getNotification();
                }
                if (Build.VERSION.SDK_INT == 19) {
                    notification2.extras.putBoolean(NotificationCompatExtras.EXTRA_LOCAL_ONLY, true);
                }
                notification = notification2;
            } else {
                notification = new Notification(17301642, string, System.currentTimeMillis());
                notification.flags |= 16;
                notification.setLatestEventInfo(context, zzi, zzc, errorPendingIntent);
            }
        }
        if (zzaU(i)) {
            zzVX.set(false);
            i2 = 10436;
        } else {
            i2 = 39789;
        }
        NotificationManager notificationManager = (NotificationManager) context.getSystemService("notification");
        if (str != null) {
            notificationManager.notify(str, i2, notification);
        } else {
            notificationManager.notify(i2, notification);
        }
    }

    public static boolean zza(Context context, int i, String str) {
        if (zzlk.zzoX()) {
            try {
                ((AppOpsManager) context.getSystemService("appops")).checkPackage(i, str);
                return true;
            } catch (SecurityException e) {
                return false;
            }
        }
        String[] packagesForUid = context.getPackageManager().getPackagesForUid(i);
        if (str == null || packagesForUid == null) {
            return false;
        }
        for (String str2 : packagesForUid) {
            if (str.equals(str2)) {
                return true;
            }
        }
        return false;
    }

    @Deprecated
    public static Intent zzaT(int i) {
        switch (i) {
            case 1:
            case 2:
                return zzm.zzcg("com.google.android.gms");
            case 3:
                return zzm.zzce("com.google.android.gms");
            case 42:
                return zzm.zznX();
            default:
                return null;
        }
    }

    private static boolean zzaU(int i) {
        switch (i) {
            case 1:
            case 2:
            case 3:
            case 18:
            case 42:
                return true;
            default:
                return false;
        }
    }

    private static void zzaa(Context context) {
        Integer num;
        synchronized (zzoW) {
            if (zzVV == null) {
                zzVV = context.getPackageName();
                try {
                    Bundle bundle = context.getPackageManager().getApplicationInfo(context.getPackageName(), 128).metaData;
                    if (bundle != null) {
                        zzVW = Integer.valueOf(bundle.getInt("com.google.android.gms.version"));
                    } else {
                        zzVW = null;
                    }
                } catch (PackageManager.NameNotFoundException e) {
                    Log.wtf("GooglePlayServicesUtil", "This should never happen.", e);
                }
            } else if (!zzVV.equals(context.getPackageName())) {
                throw new IllegalArgumentException("isGooglePlayServicesAvailable should only be called with Context from your application's package. A previous call used package '" + zzVV + "' and this call used package '" + context.getPackageName() + "'.");
            }
            num = zzVW;
        }
        if (num == null) {
            throw new IllegalStateException("A required meta-data tag in your app's AndroidManifest.xml does not exist.  You must have the following declaration within the <application> element:     <meta-data android:name=\"com.google.android.gms.version\" android:value=\"@integer/google_play_services_version\" />");
        }
        if (num.intValue() != GOOGLE_PLAY_SERVICES_VERSION_CODE) {
            throw new IllegalStateException("The meta-data tag in your app's AndroidManifest.xml does not have the right value.  Expected " + GOOGLE_PLAY_SERVICES_VERSION_CODE + " but found " + num + ".  You must have the following declaration within the <application> element:     <meta-data android:name=\"com.google.android.gms.version\" android:value=\"@integer/google_play_services_version\" />");
        }
    }

    private static void zzab(Context context) {
        zza zzaVar = new zza(context);
        zzaVar.sendMessageDelayed(zzaVar.obtainMessage(1), 120000L);
    }

    @Deprecated
    public static void zzac(Context context) {
        if (zzVX.getAndSet(true)) {
            return;
        }
        try {
            ((NotificationManager) context.getSystemService("notification")).cancel(10436);
        } catch (SecurityException e) {
        }
    }

    public static String zzad(Context context) {
        ApplicationInfo applicationInfo;
        String str = context.getApplicationInfo().name;
        if (TextUtils.isEmpty(str)) {
            String packageName = context.getPackageName();
            PackageManager packageManager = context.getApplicationContext().getPackageManager();
            try {
                applicationInfo = packageManager.getApplicationInfo(context.getPackageName(), 0);
            } catch (PackageManager.NameNotFoundException e) {
                applicationInfo = null;
            }
            return applicationInfo != null ? packageManager.getApplicationLabel(applicationInfo).toString() : packageName;
        }
        return str;
    }

    public static boolean zzae(Context context) {
        return zzlk.zzoZ() && context.getPackageManager().hasSystemFeature("com.google.sidewinder");
    }

    public static boolean zzb(PackageManager packageManager) {
        synchronized (zzoW) {
            if (zzVU == -1) {
                try {
                    if (zzd.zzmn().zza(packageManager.getPackageInfo("com.google.android.gms", 64), zzc.zzVK[1]) != null) {
                        zzVU = 1;
                    } else {
                        zzVU = 0;
                    }
                } catch (PackageManager.NameNotFoundException e) {
                    zzVU = 0;
                }
            }
        }
        return zzVU != 0;
    }

    @Deprecated
    public static boolean zzb(PackageManager packageManager, String str) {
        return zzd.zzmn().zzb(packageManager, str);
    }

    public static boolean zzc(PackageManager packageManager) {
        return zzb(packageManager) || !zzmm();
    }

    public static boolean zzd(Context context, int i) {
        return zza(context, i, "com.google.android.gms") && zzb(context.getPackageManager(), "com.google.android.gms");
    }

    @Deprecated
    public static boolean zze(Context context, int i) {
        if (i == 18) {
            return true;
        }
        if (i == 1) {
            return zzh(context, "com.google.android.gms");
        }
        return false;
    }

    @Deprecated
    public static boolean zzf(Context context, int i) {
        if (i == 9) {
            return zzh(context, GOOGLE_PLAY_STORE_PACKAGE);
        }
        return false;
    }

    public static boolean zzh(Context context, String str) {
        if (zzlk.zzoZ()) {
            for (PackageInstaller.SessionInfo sessionInfo : context.getPackageManager().getPackageInstaller().getAllSessions()) {
                if (str.equals(sessionInfo.getAppPackageName())) {
                    return true;
                }
            }
        } else {
            try {
                if (context.getPackageManager().getApplicationInfo(str, 8192).enabled) {
                    return true;
                }
            } catch (PackageManager.NameNotFoundException e) {
            }
        }
        return false;
    }

    private static int zzml() {
        return 7571000;
    }

    public static boolean zzmm() {
        return zzVS ? zzVT : "user".equals(Build.TYPE);
    }
}
