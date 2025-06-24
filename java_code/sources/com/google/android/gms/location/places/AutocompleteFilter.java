package com.google.android.gms.location.places;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
/* loaded from: classes.dex */
public class AutocompleteFilter implements SafeParcelable {
    public static final zzc CREATOR = new zzc();
    final int zzCY;
    final boolean zzazr;
    final List<Integer> zzazs;
    private final Set<Integer> zzazt;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AutocompleteFilter(int versionCode, boolean restrictToPlaces, Collection<Integer> placeTypes) {
        this.zzCY = versionCode;
        this.zzazr = restrictToPlaces;
        this.zzazs = placeTypes == null ? Collections.emptyList() : new ArrayList<>(placeTypes);
        if (this.zzazs.isEmpty()) {
            this.zzazt = Collections.emptySet();
        } else {
            this.zzazt = Collections.unmodifiableSet(new HashSet(this.zzazs));
        }
    }

    public static AutocompleteFilter create(Collection<Integer> placeTypes) {
        return zza(true, placeTypes);
    }

    public static AutocompleteFilter zza(boolean z, Collection<Integer> collection) {
        return new AutocompleteFilter(0, z, collection);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zzc zzcVar = CREATOR;
        return 0;
    }

    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object instanceof AutocompleteFilter) {
            AutocompleteFilter autocompleteFilter = (AutocompleteFilter) object;
            return this.zzazt.equals(autocompleteFilter.zzazt) && this.zzazr == autocompleteFilter.zzazr;
        }
        return false;
    }

    public Set<Integer> getPlaceTypes() {
        return this.zzazt;
    }

    public int hashCode() {
        return zzt.hashCode(Boolean.valueOf(this.zzazr), this.zzazt);
    }

    public String toString() {
        zzt.zza zzt = zzt.zzt(this);
        if (!this.zzazr) {
            zzt.zzg("restrictedToPlaces", Boolean.valueOf(this.zzazr));
        }
        zzt.zzg("placeTypes", this.zzazt);
        return zzt.toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzc zzcVar = CREATOR;
        zzc.zza(this, parcel, flags);
    }

    public boolean zzuE() {
        return this.zzazr;
    }
}
