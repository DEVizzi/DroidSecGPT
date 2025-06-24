package com.google.android.gms.ads.internal.formats;

import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.RemoteException;
import com.google.android.gms.internal.zzck;
import com.google.android.gms.internal.zzgd;
@zzgd
/* loaded from: classes.dex */
public class zzc extends zzck.zza {
    private final Uri mUri;
    private final Drawable zzvg;

    public zzc(Drawable drawable, Uri uri) {
        this.zzvg = drawable;
        this.mUri = uri;
    }

    @Override // com.google.android.gms.internal.zzck
    public Uri getUri() throws RemoteException {
        return this.mUri;
    }

    @Override // com.google.android.gms.internal.zzck
    public com.google.android.gms.dynamic.zzd zzdw() throws RemoteException {
        return com.google.android.gms.dynamic.zze.zzw(this.zzvg);
    }
}
