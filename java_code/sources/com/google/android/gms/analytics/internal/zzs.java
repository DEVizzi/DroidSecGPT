package com.google.android.gms.analytics.internal;

import android.util.Log;
import com.google.android.gms.analytics.Logger;
/* loaded from: classes.dex */
class zzs implements Logger {
    private boolean zzIz;
    private int zzKR = 2;

    @Override // com.google.android.gms.analytics.Logger
    public void error(Exception exception) {
    }

    @Override // com.google.android.gms.analytics.Logger
    public void error(String msg) {
    }

    @Override // com.google.android.gms.analytics.Logger
    public int getLogLevel() {
        return this.zzKR;
    }

    @Override // com.google.android.gms.analytics.Logger
    public void info(String msg) {
    }

    @Override // com.google.android.gms.analytics.Logger
    public void setLogLevel(int level) {
        this.zzKR = level;
        if (this.zzIz) {
            return;
        }
        Log.i(zzy.zzLb.get(), "Logger is deprecated. To enable debug logging, please run:\nadb shell setprop log.tag." + zzy.zzLb.get() + " DEBUG");
        this.zzIz = true;
    }

    @Override // com.google.android.gms.analytics.Logger
    public void verbose(String msg) {
    }

    @Override // com.google.android.gms.analytics.Logger
    public void warn(String msg) {
    }
}
