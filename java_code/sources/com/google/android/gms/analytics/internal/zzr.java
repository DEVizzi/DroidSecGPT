package com.google.android.gms.analytics.internal;

import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Process;
import android.text.TextUtils;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
/* loaded from: classes.dex */
public class zzr {
    private final zzf zzIa;
    private Boolean zzKO;
    private String zzKP;
    private Set<Integer> zzKQ;

    /* JADX INFO: Access modifiers changed from: protected */
    public zzr(zzf zzfVar) {
        com.google.android.gms.common.internal.zzu.zzu(zzfVar);
        this.zzIa = zzfVar;
    }

    public boolean zziW() {
        return com.google.android.gms.common.internal.zzd.zzZR;
    }

    public boolean zziX() {
        if (this.zzKO == null) {
            synchronized (this) {
                if (this.zzKO == null) {
                    Context context = this.zzIa.getContext();
                    ApplicationInfo applicationInfo = context.getApplicationInfo();
                    if (applicationInfo != null) {
                        String str = applicationInfo.processName;
                        ActivityManager activityManager = (ActivityManager) context.getSystemService("activity");
                        if (activityManager != null) {
                            int myPid = Process.myPid();
                            Iterator<ActivityManager.RunningAppProcessInfo> it = activityManager.getRunningAppProcesses().iterator();
                            while (true) {
                                if (!it.hasNext()) {
                                    break;
                                }
                                ActivityManager.RunningAppProcessInfo next = it.next();
                                if (myPid == next.pid) {
                                    this.zzKO = Boolean.valueOf(str != null && str.equals(next.processName));
                                }
                            }
                        }
                    }
                    if (this.zzKO == null) {
                        this.zzKO = Boolean.TRUE;
                        this.zzIa.zzhQ().zzaX("My process not in the list of running processes");
                    }
                }
            }
        }
        return this.zzKO.booleanValue();
    }

    public boolean zziY() {
        return zzy.zzLa.get().booleanValue();
    }

    public int zziZ() {
        return zzy.zzLt.get().intValue();
    }

    public int zzjA() {
        return zzy.zzLE.get().intValue();
    }

    public long zzjB() {
        return zzy.zzLF.get().longValue();
    }

    public long zzjC() {
        return zzy.zzLO.get().longValue();
    }

    public int zzja() {
        return zzy.zzLx.get().intValue();
    }

    public int zzjb() {
        return zzy.zzLy.get().intValue();
    }

    public int zzjc() {
        return zzy.zzLz.get().intValue();
    }

    public long zzjd() {
        return zzy.zzLi.get().longValue();
    }

    public long zzje() {
        return zzy.zzLh.get().longValue();
    }

    public long zzjf() {
        return zzy.zzLl.get().longValue();
    }

    public long zzjg() {
        return zzy.zzLm.get().longValue();
    }

    public int zzjh() {
        return zzy.zzLn.get().intValue();
    }

    public int zzji() {
        return zzy.zzLo.get().intValue();
    }

    public long zzjj() {
        return zzy.zzLB.get().intValue();
    }

    public String zzjk() {
        return zzy.zzLq.get();
    }

    public String zzjl() {
        return zzy.zzLp.get();
    }

    public String zzjm() {
        return zzy.zzLr.get();
    }

    public String zzjn() {
        return zzy.zzLs.get();
    }

    public zzm zzjo() {
        return zzm.zzbc(zzy.zzLu.get());
    }

    public zzo zzjp() {
        return zzo.zzbd(zzy.zzLv.get());
    }

    public Set<Integer> zzjq() {
        String str = zzy.zzLA.get();
        if (this.zzKQ == null || this.zzKP == null || !this.zzKP.equals(str)) {
            String[] split = TextUtils.split(str, ",");
            HashSet hashSet = new HashSet();
            for (String str2 : split) {
                try {
                    hashSet.add(Integer.valueOf(Integer.parseInt(str2)));
                } catch (NumberFormatException e) {
                }
            }
            this.zzKP = str;
            this.zzKQ = hashSet;
        }
        return this.zzKQ;
    }

    public long zzjr() {
        return zzy.zzLJ.get().longValue();
    }

    public long zzjs() {
        return zzy.zzLK.get().longValue();
    }

    public long zzjt() {
        return zzy.zzLN.get().longValue();
    }

    public int zzju() {
        return zzy.zzLe.get().intValue();
    }

    public int zzjv() {
        return zzy.zzLg.get().intValue();
    }

    public String zzjw() {
        return "google_analytics_v4.db";
    }

    public String zzjx() {
        return "google_analytics2_v4.db";
    }

    public long zzjy() {
        return 86400000L;
    }

    public int zzjz() {
        return zzy.zzLD.get().intValue();
    }
}
