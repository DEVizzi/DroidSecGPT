package com.google.android.gms.cast.internal;

import com.google.android.gms.common.api.Api;
import java.nio.charset.Charset;
import java.nio.charset.IllegalCharsetNameException;
import java.nio.charset.UnsupportedCharsetException;
/* loaded from: classes.dex */
public final class zzk {
    public static final Api.ClientKey<zze> zzNX = new Api.ClientKey<>();
    public static final String zzUQ = zzf.zzbE("com.google.cast.receiver");
    public static final String zzUR = zzf.zzbE("com.google.cast.tp.connection");
    public static final Charset zzUS;

    static {
        Charset charset = null;
        try {
            charset = Charset.forName("UTF-8");
        } catch (IllegalCharsetNameException e) {
        } catch (UnsupportedCharsetException e2) {
        }
        zzUS = charset;
    }
}
