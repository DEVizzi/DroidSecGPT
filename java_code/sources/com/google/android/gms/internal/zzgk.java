package com.google.android.gms.internal;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.media.AudioManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;
import android.os.Build;
import android.telephony.TelephonyManager;
import android.util.DisplayMetrics;
import java.util.Locale;
@zzgd
/* loaded from: classes.dex */
public final class zzgk {
    public final int zzCw;
    public final int zzCx;
    public final float zzCy;
    public final int zzEA;
    public final int zzEB;
    public final int zzEC;
    public final double zzED;
    public final boolean zzEE;
    public final boolean zzEF;
    public final int zzEG;
    public final int zzEn;
    public final boolean zzEo;
    public final boolean zzEp;
    public final String zzEq;
    public final String zzEr;
    public final boolean zzEs;
    public final boolean zzEt;
    public final boolean zzEu;
    public final String zzEv;
    public final String zzEw;
    public final int zzEx;
    public final int zzEy;
    public final int zzEz;

    /* loaded from: classes.dex */
    public static final class zza {
        private int zzCw;
        private int zzCx;
        private float zzCy;
        private int zzEA;
        private int zzEB;
        private int zzEC;
        private double zzED;
        private boolean zzEE;
        private boolean zzEF;
        private int zzEG;
        private int zzEn;
        private boolean zzEo;
        private boolean zzEp;
        private String zzEq;
        private String zzEr;
        private boolean zzEs;
        private boolean zzEt;
        private boolean zzEu;
        private String zzEv;
        private String zzEw;
        private int zzEx;
        private int zzEy;
        private int zzEz;

        public zza(Context context) {
            PackageManager packageManager = context.getPackageManager();
            zzA(context);
            zza(context, packageManager);
            zzB(context);
            DisplayMetrics displayMetrics = context.getResources().getDisplayMetrics();
            Locale locale = Locale.getDefault();
            this.zzEo = zza(packageManager, "geo:0,0?q=donuts") != null;
            this.zzEp = zza(packageManager, "http://www.google.com") != null;
            this.zzEr = locale.getCountry();
            this.zzEs = com.google.android.gms.ads.internal.client.zzk.zzcA().zzgv();
            this.zzEv = locale.getLanguage();
            this.zzEw = zza(packageManager);
            this.zzCy = displayMetrics.density;
            this.zzCw = displayMetrics.widthPixels;
            this.zzCx = displayMetrics.heightPixels;
        }

        public zza(Context context, zzgk zzgkVar) {
            PackageManager packageManager = context.getPackageManager();
            zzA(context);
            zza(context, packageManager);
            zzB(context);
            this.zzEo = zzgkVar.zzEo;
            this.zzEp = zzgkVar.zzEp;
            this.zzEr = zzgkVar.zzEr;
            this.zzEs = zzgkVar.zzEs;
            this.zzEv = zzgkVar.zzEv;
            this.zzEw = zzgkVar.zzEw;
            this.zzCy = zzgkVar.zzCy;
            this.zzCw = zzgkVar.zzCw;
            this.zzCx = zzgkVar.zzCx;
        }

        private void zzA(Context context) {
            AudioManager audioManager = (AudioManager) context.getSystemService("audio");
            this.zzEn = audioManager.getMode();
            this.zzEt = audioManager.isMusicActive();
            this.zzEu = audioManager.isSpeakerphoneOn();
            this.zzEx = audioManager.getStreamVolume(3);
            this.zzEB = audioManager.getRingerMode();
            this.zzEC = audioManager.getStreamVolume(2);
        }

        private void zzB(Context context) {
            boolean z = false;
            Intent registerReceiver = context.registerReceiver(null, new IntentFilter("android.intent.action.BATTERY_CHANGED"));
            if (registerReceiver == null) {
                this.zzED = -1.0d;
                this.zzEE = false;
                return;
            }
            int intExtra = registerReceiver.getIntExtra("status", -1);
            this.zzED = registerReceiver.getIntExtra("level", -1) / registerReceiver.getIntExtra("scale", -1);
            this.zzEE = (intExtra == 2 || intExtra == 5) ? true : true;
        }

        private static int zza(Context context, ConnectivityManager connectivityManager, PackageManager packageManager) {
            if (com.google.android.gms.ads.internal.zzo.zzbv().zza(packageManager, context.getPackageName(), "android.permission.ACCESS_NETWORK_STATE")) {
                NetworkInfo activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
                if (activeNetworkInfo != null) {
                    return activeNetworkInfo.getType();
                }
                return -1;
            }
            return -2;
        }

        private static ResolveInfo zza(PackageManager packageManager, String str) {
            return packageManager.resolveActivity(new Intent("android.intent.action.VIEW", Uri.parse(str)), 65536);
        }

        private static String zza(PackageManager packageManager) {
            ActivityInfo activityInfo;
            ResolveInfo zza = zza(packageManager, "market://details?id=com.google.android.gms.ads");
            if (zza == null || (activityInfo = zza.activityInfo) == null) {
                return null;
            }
            try {
                PackageInfo packageInfo = packageManager.getPackageInfo(activityInfo.packageName, 0);
                if (packageInfo != null) {
                    return packageInfo.versionCode + "." + activityInfo.packageName;
                }
                return null;
            } catch (PackageManager.NameNotFoundException e) {
                return null;
            }
        }

        private void zza(Context context, PackageManager packageManager) {
            TelephonyManager telephonyManager = (TelephonyManager) context.getSystemService("phone");
            ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService("connectivity");
            this.zzEq = telephonyManager.getNetworkOperator();
            this.zzEy = zza(context, connectivityManager, packageManager);
            this.zzEz = telephonyManager.getNetworkType();
            this.zzEA = telephonyManager.getPhoneType();
            if (Build.VERSION.SDK_INT < 16) {
                this.zzEF = false;
                this.zzEG = -1;
                return;
            }
            this.zzEF = connectivityManager.isActiveNetworkMetered();
            if (connectivityManager.getActiveNetworkInfo() != null) {
                this.zzEG = connectivityManager.getActiveNetworkInfo().getDetailedState().ordinal();
            } else {
                this.zzEG = -1;
            }
        }

        public zzgk zzfJ() {
            return new zzgk(this.zzEn, this.zzEo, this.zzEp, this.zzEq, this.zzEr, this.zzEs, this.zzEt, this.zzEu, this.zzEv, this.zzEw, this.zzEx, this.zzEy, this.zzEz, this.zzEA, this.zzEB, this.zzEC, this.zzCy, this.zzCw, this.zzCx, this.zzED, this.zzEE, this.zzEF, this.zzEG);
        }
    }

    zzgk(int i, boolean z, boolean z2, String str, String str2, boolean z3, boolean z4, boolean z5, String str3, String str4, int i2, int i3, int i4, int i5, int i6, int i7, float f, int i8, int i9, double d, boolean z6, boolean z7, int i10) {
        this.zzEn = i;
        this.zzEo = z;
        this.zzEp = z2;
        this.zzEq = str;
        this.zzEr = str2;
        this.zzEs = z3;
        this.zzEt = z4;
        this.zzEu = z5;
        this.zzEv = str3;
        this.zzEw = str4;
        this.zzEx = i2;
        this.zzEy = i3;
        this.zzEz = i4;
        this.zzEA = i5;
        this.zzEB = i6;
        this.zzEC = i7;
        this.zzCy = f;
        this.zzCw = i8;
        this.zzCx = i9;
        this.zzED = d;
        this.zzEE = z6;
        this.zzEF = z7;
        this.zzEG = i10;
    }
}
