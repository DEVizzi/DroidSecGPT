package com.google.android.gms.tagmanager;

import android.content.Context;
import com.google.android.gms.analytics.GoogleAnalytics;
import com.google.android.gms.analytics.Logger;
import com.google.android.gms.analytics.Tracker;
/* loaded from: classes.dex */
class zzdc {
    private Context mContext;
    private Tracker zzIq;
    private GoogleAnalytics zzIs;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class zza implements Logger {
        zza() {
        }

        private static int zzja(int i) {
            switch (i) {
                case 2:
                    return 0;
                case 3:
                case 4:
                    return 1;
                case 5:
                    return 2;
                case 6:
                default:
                    return 3;
            }
        }

        @Override // com.google.android.gms.analytics.Logger
        public void error(Exception exception) {
            zzbg.zzb("", exception);
        }

        @Override // com.google.android.gms.analytics.Logger
        public void error(String message) {
            zzbg.zzaz(message);
        }

        @Override // com.google.android.gms.analytics.Logger
        public int getLogLevel() {
            return zzja(zzbg.getLogLevel());
        }

        @Override // com.google.android.gms.analytics.Logger
        public void info(String message) {
            zzbg.zzaA(message);
        }

        @Override // com.google.android.gms.analytics.Logger
        public void setLogLevel(int logLevel) {
            zzbg.zzaC("GA uses GTM logger. Please use TagManager.setLogLevel(int) instead.");
        }

        @Override // com.google.android.gms.analytics.Logger
        public void verbose(String message) {
            zzbg.zzaB(message);
        }

        @Override // com.google.android.gms.analytics.Logger
        public void warn(String message) {
            zzbg.zzaC(message);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzdc(Context context) {
        this.mContext = context;
    }

    private synchronized void zzeH(String str) {
        if (this.zzIs == null) {
            this.zzIs = GoogleAnalytics.getInstance(this.mContext);
            this.zzIs.setLogger(new zza());
            this.zzIq = this.zzIs.newTracker(str);
        }
    }

    public Tracker zzeG(String str) {
        zzeH(str);
        return this.zzIq;
    }
}
