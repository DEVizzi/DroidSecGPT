package com.google.android.gms.location.places.internal;

import android.content.Context;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.location.places.Place;
import com.google.android.gms.location.places.PlaceLikelihood;
/* loaded from: classes.dex */
public class zzm extends zzt implements PlaceLikelihood {
    private final Context mContext;

    public zzm(DataHolder dataHolder, int i, Context context) {
        super(dataHolder, i);
        this.mContext = context;
    }

    @Override // com.google.android.gms.location.places.PlaceLikelihood
    public float getLikelihood() {
        return zzb("place_likelihood", -1.0f);
    }

    @Override // com.google.android.gms.location.places.PlaceLikelihood
    public Place getPlace() {
        return new zzr(this.zzWu, this.zzYs, this.mContext);
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzuY */
    public PlaceLikelihood freeze() {
        return PlaceLikelihoodEntity.zza((PlaceImpl) getPlace().freeze(), getLikelihood());
    }
}
