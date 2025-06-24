package com.google.android.gms.cast.internal;

import android.text.TextUtils;
import java.io.IOException;
/* loaded from: classes.dex */
public abstract class zzd {
    protected final zzl zzUi;
    private final String zzUj;
    private zzn zzUk;

    /* JADX INFO: Access modifiers changed from: protected */
    public zzd(String str, String str2, String str3) {
        zzf.zzbD(str);
        this.zzUj = str;
        this.zzUi = new zzl(str2);
        setSessionLabel(str3);
    }

    public final String getNamespace() {
        return this.zzUj;
    }

    public void setSessionLabel(String sessionLabel) {
        if (TextUtils.isEmpty(sessionLabel)) {
            return;
        }
        this.zzUi.zzbJ(sessionLabel);
    }

    public final void zza(zzn zznVar) {
        this.zzUk = zznVar;
        if (this.zzUk == null) {
            zzlJ();
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void zza(String str, long j, String str2) throws IOException {
        this.zzUi.zza("Sending text message: %s to: %s", str, str2);
        this.zzUk.zza(this.zzUj, str, j, str2);
    }

    public void zzb(long j, int i) {
    }

    public void zzbB(String str) {
    }

    public void zzlJ() {
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final long zzlK() {
        return this.zzUk.zzlu();
    }
}
