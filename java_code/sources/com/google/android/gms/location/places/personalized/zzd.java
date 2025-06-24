package com.google.android.gms.location.places.personalized;

import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.location.places.PlacesStatusCodes;
/* loaded from: classes.dex */
public final class zzd extends com.google.android.gms.common.data.zzd<PlaceUserData> implements Result {
    private final Status zzOt;

    public zzd(DataHolder dataHolder) {
        this(dataHolder, PlacesStatusCodes.zzgU(dataHolder.getStatusCode()));
    }

    private zzd(DataHolder dataHolder, Status status) {
        super(dataHolder, PlaceUserData.CREATOR);
        zzu.zzV(dataHolder == null || dataHolder.getStatusCode() == status.getStatusCode());
        this.zzOt = status;
    }

    public static zzd zzaK(Status status) {
        return new zzd(null, status);
    }

    @Override // com.google.android.gms.common.api.Result
    public Status getStatus() {
        return this.zzOt;
    }
}
