package com.google.android.gms.internal;

import android.graphics.drawable.Drawable;
import android.net.Uri;
import com.google.android.gms.ads.formats.NativeAd;
@zzgd
/* loaded from: classes.dex */
public class zzcl implements NativeAd.Image {
    private final Uri mUri;
    private final zzck zzvI;
    private final Drawable zzvJ;

    /* JADX WARN: Can't wrap try/catch for region: R(10:1|2|3|(6:5|6|7|8|9|10)|16|6|7|8|9|10) */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x0027, code lost:
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:14:0x0028, code lost:
        com.google.android.gms.ads.internal.util.client.zzb.zzb("Failed to get uri.", r0);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public zzcl(com.google.android.gms.internal.zzck r4) {
        /*
            r3 = this;
            r1 = 0
            r3.<init>()
            r3.zzvI = r4
            com.google.android.gms.internal.zzck r0 = r3.zzvI     // Catch: android.os.RemoteException -> L1f
            com.google.android.gms.dynamic.zzd r0 = r0.zzdw()     // Catch: android.os.RemoteException -> L1f
            if (r0 == 0) goto L25
            java.lang.Object r0 = com.google.android.gms.dynamic.zze.zzn(r0)     // Catch: android.os.RemoteException -> L1f
            android.graphics.drawable.Drawable r0 = (android.graphics.drawable.Drawable) r0     // Catch: android.os.RemoteException -> L1f
        L14:
            r3.zzvJ = r0
            com.google.android.gms.internal.zzck r0 = r3.zzvI     // Catch: android.os.RemoteException -> L27
            android.net.Uri r1 = r0.getUri()     // Catch: android.os.RemoteException -> L27
        L1c:
            r3.mUri = r1
            return
        L1f:
            r0 = move-exception
            java.lang.String r2 = "Failed to get drawable."
            com.google.android.gms.ads.internal.util.client.zzb.zzb(r2, r0)
        L25:
            r0 = r1
            goto L14
        L27:
            r0 = move-exception
            java.lang.String r2 = "Failed to get uri."
            com.google.android.gms.ads.internal.util.client.zzb.zzb(r2, r0)
            goto L1c
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.zzcl.<init>(com.google.android.gms.internal.zzck):void");
    }

    @Override // com.google.android.gms.ads.formats.NativeAd.Image
    public Drawable getDrawable() {
        return this.zzvJ;
    }

    @Override // com.google.android.gms.ads.formats.NativeAd.Image
    public Uri getUri() {
        return this.mUri;
    }
}
