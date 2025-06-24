package com.google.android.gms.tagmanager;

import android.app.ActivityManager;
import android.app.KeyguardManager;
import android.content.Context;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.PowerManager;
import android.os.Process;
import android.text.TextUtils;
import com.google.android.gms.internal.zzag;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zzdb extends zzak {
    private static final String ID = com.google.android.gms.internal.zzad.TIMER_LISTENER.toString();
    private static final String NAME = com.google.android.gms.internal.zzae.NAME.toString();
    private static final String zzaOe = com.google.android.gms.internal.zzae.INTERVAL.toString();
    private static final String zzaOf = com.google.android.gms.internal.zzae.LIMIT.toString();
    private static final String zzaOg = com.google.android.gms.internal.zzae.UNIQUE_TRIGGER_ID.toString();
    private final Context mContext;
    private Handler mHandler;
    private DataLayer zzaKz;
    private boolean zzaOh;
    private boolean zzaOi;
    private final HandlerThread zzaOj;
    private final Set<String> zzaOk;

    /* loaded from: classes.dex */
    private final class zza implements Runnable {
        private final long zzMC = System.currentTimeMillis();
        private final String zzaOl;
        private final String zzaOm;
        private final long zzaOn;
        private long zzaOo;
        private final long zzaxU;

        zza(String str, String str2, long j, long j2) {
            this.zzaOl = str;
            this.zzaOm = str2;
            this.zzaxU = j;
            this.zzaOn = j2;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (this.zzaOn > 0 && this.zzaOo >= this.zzaOn) {
                if ("0".equals(this.zzaOm)) {
                    return;
                }
                zzdb.this.zzaOk.remove(this.zzaOm);
                return;
            }
            this.zzaOo++;
            if (zzcq()) {
                long currentTimeMillis = System.currentTimeMillis();
                zzdb.this.zzaKz.push(DataLayer.mapOf("event", this.zzaOl, "gtm.timerInterval", String.valueOf(this.zzaxU), "gtm.timerLimit", String.valueOf(this.zzaOn), "gtm.timerStartTime", String.valueOf(this.zzMC), "gtm.timerCurrentTime", String.valueOf(currentTimeMillis), "gtm.timerElapsedTime", String.valueOf(currentTimeMillis - this.zzMC), "gtm.timerEventNumber", String.valueOf(this.zzaOo), "gtm.triggers", this.zzaOm));
            }
            zzdb.this.mHandler.postDelayed(this, this.zzaxU);
        }

        protected boolean zzcq() {
            if (zzdb.this.zzaOi) {
                return zzdb.this.zzaOh;
            }
            KeyguardManager keyguardManager = (KeyguardManager) zzdb.this.mContext.getSystemService("keyguard");
            PowerManager powerManager = (PowerManager) zzdb.this.mContext.getSystemService("power");
            for (ActivityManager.RunningAppProcessInfo runningAppProcessInfo : ((ActivityManager) zzdb.this.mContext.getSystemService("activity")).getRunningAppProcesses()) {
                if (Process.myPid() == runningAppProcessInfo.pid && runningAppProcessInfo.importance == 100 && !keyguardManager.inKeyguardRestrictedInputMode() && powerManager.isScreenOn()) {
                    return true;
                }
            }
            return false;
        }
    }

    public zzdb(Context context, DataLayer dataLayer) {
        super(ID, zzaOe, NAME);
        this.zzaOk = new HashSet();
        this.mContext = context;
        this.zzaKz = dataLayer;
        this.zzaOj = new HandlerThread("Google GTM SDK Timer", 10);
        this.zzaOj.start();
        this.mHandler = new Handler(this.zzaOj.getLooper());
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public zzag.zza zzE(Map<String, zzag.zza> map) {
        long j;
        long j2;
        String zzg = zzdf.zzg(map.get(NAME));
        String zzg2 = zzdf.zzg(map.get(zzaOg));
        String zzg3 = zzdf.zzg(map.get(zzaOe));
        String zzg4 = zzdf.zzg(map.get(zzaOf));
        try {
            j = Long.parseLong(zzg3);
        } catch (NumberFormatException e) {
            j = 0;
        }
        try {
            j2 = Long.parseLong(zzg4);
        } catch (NumberFormatException e2) {
            j2 = 0;
        }
        if (j > 0 && !TextUtils.isEmpty(zzg)) {
            zzg2 = (zzg2 == null || zzg2.isEmpty()) ? "0" : "0";
            if (!this.zzaOk.contains(zzg2)) {
                if (!"0".equals(zzg2)) {
                    this.zzaOk.add(zzg2);
                }
                this.mHandler.postDelayed(new zza(zzg, zzg2, j, j2), j);
            }
        }
        return zzdf.zzzQ();
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public boolean zzyh() {
        return false;
    }
}
