package com.google.android.gms.location.places.internal;

import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.location.places.AutocompletePrediction;
import com.google.android.gms.location.places.internal.AutocompletePredictionEntity;
import java.util.Collections;
import java.util.List;
/* loaded from: classes.dex */
public class zzb extends zzt implements AutocompletePrediction {
    public zzb(DataHolder dataHolder, int i) {
        super(dataHolder, i);
    }

    @Override // com.google.android.gms.location.places.AutocompletePrediction
    public String getDescription() {
        return zzB("ap_description", "");
    }

    @Override // com.google.android.gms.location.places.AutocompletePrediction
    public List<AutocompletePredictionEntity.SubstringEntity> getMatchedSubstrings() {
        return zza("ap_matched_subscriptions", AutocompletePredictionEntity.SubstringEntity.CREATOR, Collections.emptyList());
    }

    @Override // com.google.android.gms.location.places.AutocompletePrediction
    public String getPlaceId() {
        return zzB("ap_place_id", null);
    }

    @Override // com.google.android.gms.location.places.AutocompletePrediction
    public List<Integer> getPlaceTypes() {
        return zza("ap_place_types", Collections.emptyList());
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzuL */
    public AutocompletePrediction freeze() {
        return AutocompletePredictionEntity.zza(getDescription(), getPlaceId(), getPlaceTypes(), getMatchedSubstrings(), zzuM());
    }

    public int zzuM() {
        return zzz("ap_personalization_type", 6);
    }
}
