package com.google.android.gms.internal;

import android.view.View;
import android.webkit.WebChromeClient;
@zzgd
/* loaded from: classes.dex */
public final class zzik extends zzii {
    public zzik(zzid zzidVar) {
        super(zzidVar);
    }

    @Override // android.webkit.WebChromeClient
    public void onShowCustomView(View view, int requestedOrientation, WebChromeClient.CustomViewCallback customViewCallback) {
        zza(view, requestedOrientation, customViewCallback);
    }
}
