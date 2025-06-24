package com.google.android.gms.location.places;

import com.google.android.gms.common.data.Freezable;
import java.util.List;
/* loaded from: classes.dex */
public interface AutocompletePrediction extends Freezable<AutocompletePrediction> {

    /* loaded from: classes.dex */
    public interface Substring {
        int getLength();

        int getOffset();
    }

    String getDescription();

    List<? extends Substring> getMatchedSubstrings();

    String getPlaceId();

    List<Integer> getPlaceTypes();
}
