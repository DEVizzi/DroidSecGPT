package com.google.android.gms.internal;

import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
/* loaded from: classes.dex */
public final class zzpt implements Api.ApiOptions.Optional {
    public static final zzpt zzaJQ = new zza().zzyc();
    private final boolean zzaJR;
    private final boolean zzaJS;
    private final String zzaJT;
    private final GoogleApiClient.ServerAuthCodeCallbacks zzaJU;

    /* loaded from: classes.dex */
    public static final class zza {
        private String zzaHb;
        private boolean zzaJV;
        private boolean zzaJW;
        private GoogleApiClient.ServerAuthCodeCallbacks zzaJX;

        private String zzea(String str) {
            com.google.android.gms.common.internal.zzu.zzu(str);
            com.google.android.gms.common.internal.zzu.zzb(this.zzaHb == null || this.zzaHb.equals(str), "two different server client ids provided");
            return str;
        }

        public zza zza(String str, GoogleApiClient.ServerAuthCodeCallbacks serverAuthCodeCallbacks) {
            this.zzaJV = true;
            this.zzaJW = true;
            this.zzaHb = zzea(str);
            this.zzaJX = (GoogleApiClient.ServerAuthCodeCallbacks) com.google.android.gms.common.internal.zzu.zzu(serverAuthCodeCallbacks);
            return this;
        }

        public zzpt zzyc() {
            return new zzpt(this.zzaJV, this.zzaJW, this.zzaHb, this.zzaJX);
        }
    }

    private zzpt(boolean z, boolean z2, String str, GoogleApiClient.ServerAuthCodeCallbacks serverAuthCodeCallbacks) {
        this.zzaJR = z;
        this.zzaJS = z2;
        this.zzaJT = str;
        this.zzaJU = serverAuthCodeCallbacks;
    }

    public boolean zzxZ() {
        return this.zzaJR;
    }

    public String zzxt() {
        return this.zzaJT;
    }

    public boolean zzya() {
        return this.zzaJS;
    }

    public GoogleApiClient.ServerAuthCodeCallbacks zzyb() {
        return this.zzaJU;
    }
}
