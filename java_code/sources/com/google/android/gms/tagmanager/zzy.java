package com.google.android.gms.tagmanager;

import android.util.Log;
/* loaded from: classes.dex */
public class zzy implements zzbh {
    private int zzKR = 5;

    @Override // com.google.android.gms.tagmanager.zzbh
    public void setLogLevel(int logLevel) {
        this.zzKR = logLevel;
    }

    @Override // com.google.android.gms.tagmanager.zzbh
    public void zzaA(String str) {
        if (this.zzKR <= 4) {
            Log.i("GoogleTagManager", str);
        }
    }

    @Override // com.google.android.gms.tagmanager.zzbh
    public void zzaB(String str) {
        if (this.zzKR <= 2) {
            Log.v("GoogleTagManager", str);
        }
    }

    @Override // com.google.android.gms.tagmanager.zzbh
    public void zzaC(String str) {
        if (this.zzKR <= 5) {
            Log.w("GoogleTagManager", str);
        }
    }

    @Override // com.google.android.gms.tagmanager.zzbh
    public void zzay(String str) {
        if (this.zzKR <= 3) {
            Log.d("GoogleTagManager", str);
        }
    }

    @Override // com.google.android.gms.tagmanager.zzbh
    public void zzaz(String str) {
        if (this.zzKR <= 6) {
            Log.e("GoogleTagManager", str);
        }
    }

    @Override // com.google.android.gms.tagmanager.zzbh
    public void zzb(String str, Throwable th) {
        if (this.zzKR <= 6) {
            Log.e("GoogleTagManager", str, th);
        }
    }

    @Override // com.google.android.gms.tagmanager.zzbh
    public void zzd(String str, Throwable th) {
        if (this.zzKR <= 5) {
            Log.w("GoogleTagManager", str, th);
        }
    }
}
