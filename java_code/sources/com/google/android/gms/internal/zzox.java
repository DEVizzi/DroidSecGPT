package com.google.android.gms.internal;

import android.content.Intent;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.panorama.PanoramaApi;
/* loaded from: classes.dex */
class zzox implements PanoramaApi.PanoramaResult {
    private final Status zzOt;
    private final Intent zzaGA;

    public zzox(Status status, Intent intent) {
        this.zzOt = (Status) com.google.android.gms.common.internal.zzu.zzu(status);
        this.zzaGA = intent;
    }

    @Override // com.google.android.gms.common.api.Result
    public Status getStatus() {
        return this.zzOt;
    }

    @Override // com.google.android.gms.panorama.PanoramaApi.PanoramaResult
    public Intent getViewerIntent() {
        return this.zzaGA;
    }
}
