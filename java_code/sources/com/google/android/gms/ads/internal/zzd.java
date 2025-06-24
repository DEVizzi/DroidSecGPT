package com.google.android.gms.ads.internal;

import android.net.Uri;
import android.text.TextUtils;
import com.google.android.gms.internal.zzbz;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzha;
import com.google.android.gms.internal.zzid;
@zzgd
/* loaded from: classes.dex */
public class zzd {
    private zza zzow;
    private boolean zzox;
    private boolean zzoy;

    /* loaded from: classes.dex */
    public interface zza {
        void zzp(String str);
    }

    @zzgd
    /* loaded from: classes.dex */
    public static class zzb implements zza {
        private final zzid zzoA;
        private final zzha.zza zzoz;

        public zzb(zzha.zza zzaVar, zzid zzidVar) {
            this.zzoz = zzaVar;
            this.zzoA = zzidVar;
        }

        @Override // com.google.android.gms.ads.internal.zzd.zza
        public void zzp(String str) {
            com.google.android.gms.ads.internal.util.client.zzb.zzay("An auto-clicking creative is blocked");
            Uri.Builder builder = new Uri.Builder();
            builder.scheme("https");
            builder.path("//pagead2.googlesyndication.com/pagead/gen_204");
            builder.appendQueryParameter("id", "gmob-apps-blocked-navigation");
            if (!TextUtils.isEmpty(str)) {
                builder.appendQueryParameter("navigationURL", str);
            }
            if (this.zzoz != null && this.zzoz.zzFs != null && !TextUtils.isEmpty(this.zzoz.zzFs.zzCP)) {
                builder.appendQueryParameter("debugDialog", this.zzoz.zzFs.zzCP);
            }
            zzo.zzbv().zzc(this.zzoA.getContext(), this.zzoA.zzgI().zzGG, builder.toString());
        }
    }

    public zzd() {
        this.zzoy = zzbz.zztI.get().booleanValue();
    }

    public zzd(boolean z) {
        this.zzoy = z;
    }

    public void recordClick() {
        this.zzox = true;
    }

    public void zza(zza zzaVar) {
        this.zzow = zzaVar;
    }

    public boolean zzbd() {
        return !this.zzoy || this.zzox;
    }

    public void zzo(String str) {
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Action was blocked because no click was detected.");
        if (this.zzow != null) {
            this.zzow.zzp(str);
        }
    }
}
