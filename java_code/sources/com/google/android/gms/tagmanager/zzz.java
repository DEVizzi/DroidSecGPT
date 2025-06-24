package com.google.android.gms.tagmanager;

import android.content.Context;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
/* loaded from: classes.dex */
class zzz implements zzar {
    private static final Object zzaKl = new Object();
    private static zzz zzaLA;
    private zzcd zzaKO;
    private String zzaLB;
    private String zzaLC;
    private zzas zzaLD;

    private zzz(Context context) {
        this(zzat.zzaH(context), new zzcs());
    }

    zzz(zzas zzasVar, zzcd zzcdVar) {
        this.zzaLD = zzasVar;
        this.zzaKO = zzcdVar;
    }

    public static zzar zzaF(Context context) {
        zzz zzzVar;
        synchronized (zzaKl) {
            if (zzaLA == null) {
                zzaLA = new zzz(context);
            }
            zzzVar = zzaLA;
        }
        return zzzVar;
    }

    @Override // com.google.android.gms.tagmanager.zzar
    public boolean zzes(String str) {
        if (!this.zzaKO.zzkb()) {
            zzbg.zzaC("Too many urls sent too quickly with the TagManagerSender, rate limiting invoked.");
            return false;
        }
        if (this.zzaLB != null && this.zzaLC != null) {
            try {
                str = this.zzaLB + "?" + this.zzaLC + "=" + URLEncoder.encode(str, "UTF-8");
                zzbg.zzaB("Sending wrapped url hit: " + str);
            } catch (UnsupportedEncodingException e) {
                zzbg.zzd("Error wrapping URL for testing.", e);
                return false;
            }
        }
        this.zzaLD.zzew(str);
        return true;
    }
}
