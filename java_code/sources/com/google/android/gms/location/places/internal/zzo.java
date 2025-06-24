package com.google.android.gms.location.places.internal;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
/* loaded from: classes.dex */
public class zzo {
    private static final String TAG = zzo.class.getSimpleName();
    private static final long zzaAQ = TimeUnit.SECONDS.toMillis(1);
    private static zzo zzaAR;
    private final Context mContext;
    private final Handler mHandler;
    private final Runnable zzaAS;
    private ArrayList<String> zzaAT;
    private ArrayList<String> zzaAU;
    private final Object zzqt;

    /* loaded from: classes.dex */
    private class zza implements Runnable {
        private zza() {
        }

        @Override // java.lang.Runnable
        public void run() {
            synchronized (zzo.this.zzqt) {
                Intent intent = new Intent("com.google.android.location.places.METHOD_CALL");
                intent.setPackage("com.google.android.gms");
                intent.putStringArrayListExtra("PLACE_IDS", zzo.this.zzaAT);
                intent.putStringArrayListExtra("METHOD_NAMES", zzo.this.zzaAU);
                zzo.this.mContext.sendBroadcast(intent);
                zzo.this.zzaAT = null;
                zzo.this.zzaAU = null;
            }
        }
    }

    private zzo(Context context) {
        this((Context) com.google.android.gms.common.internal.zzu.zzu(context), new Handler(Looper.getMainLooper()));
    }

    zzo(Context context, Handler handler) {
        this.zzaAS = new zza();
        this.zzqt = new Object();
        this.zzaAT = null;
        this.zzaAU = null;
        this.mContext = context;
        this.mHandler = handler;
    }

    public static synchronized zzo zzax(Context context) {
        zzo zzoVar;
        synchronized (zzo.class) {
            com.google.android.gms.common.internal.zzu.zzu(context);
            if (Build.VERSION.SDK_INT < 14) {
                zzoVar = null;
            } else {
                if (zzaAR == null) {
                    zzaAR = new zzo(context.getApplicationContext());
                }
                zzoVar = zzaAR;
            }
        }
        return zzoVar;
    }

    public void zzA(String str, String str2) {
        synchronized (this.zzqt) {
            if (this.zzaAT == null) {
                this.zzaAT = new ArrayList<>();
                this.zzaAU = new ArrayList<>();
                this.mHandler.postDelayed(this.zzaAS, zzaAQ);
            }
            this.zzaAT.add(str);
            this.zzaAU.add(str2);
            if (this.zzaAT.size() >= 10000) {
                if (Log.isLoggable(TAG, 5)) {
                    Log.w(TAG, "Event buffer full, flushing");
                }
                this.zzaAS.run();
                this.mHandler.removeCallbacks(this.zzaAS);
            }
        }
    }
}
