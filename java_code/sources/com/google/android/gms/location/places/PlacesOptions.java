package com.google.android.gms.location.places;

import com.google.android.gms.common.api.Api;
/* loaded from: classes.dex */
public final class PlacesOptions implements Api.ApiOptions.Optional {
    public final String zzazX;

    /* loaded from: classes.dex */
    public static class Builder {
        private String zzazY;

        public PlacesOptions build() {
            return new PlacesOptions(this);
        }
    }

    private PlacesOptions(Builder builder) {
        this.zzazX = builder.zzazY;
    }
}
