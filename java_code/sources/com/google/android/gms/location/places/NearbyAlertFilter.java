package com.google.android.gms.location.places;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
/* loaded from: classes.dex */
public final class NearbyAlertFilter extends zza implements SafeParcelable {
    public static final zzd CREATOR = new zzd();
    final int zzCY;
    final List<Integer> zzazs;
    private final Set<Integer> zzazt;
    final List<String> zzazu;
    final List<UserDataType> zzazv;
    private final Set<String> zzazw;
    private final Set<UserDataType> zzazx;

    /* JADX INFO: Access modifiers changed from: package-private */
    public NearbyAlertFilter(int versionCode, List<String> placeIdsList, List<Integer> placeTypesList, List<UserDataType> requestedUserDataTypesList) {
        this.zzCY = versionCode;
        this.zzazs = placeTypesList == null ? Collections.emptyList() : Collections.unmodifiableList(placeTypesList);
        this.zzazv = requestedUserDataTypesList == null ? Collections.emptyList() : Collections.unmodifiableList(requestedUserDataTypesList);
        this.zzazu = placeIdsList == null ? Collections.emptyList() : Collections.unmodifiableList(placeIdsList);
        this.zzazt = zzl(this.zzazs);
        this.zzazx = zzl(this.zzazv);
        this.zzazw = zzl(this.zzazu);
    }

    public static NearbyAlertFilter zza(Collection<String> collection, Collection<Integer> collection2, Collection<UserDataType> collection3) {
        if ((collection == null || collection.isEmpty()) && ((collection2 == null || collection2.isEmpty()) && (collection3 == null || collection3.isEmpty()))) {
            throw new IllegalArgumentException("NearbyAlertFilters must contain at least onePlaceId, PlaceType, or UserDataType to match results with.");
        }
        return new NearbyAlertFilter(0, zzc(collection), zzc(collection2), zzc(collection3));
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zzd zzdVar = CREATOR;
        return 0;
    }

    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object instanceof NearbyAlertFilter) {
            NearbyAlertFilter nearbyAlertFilter = (NearbyAlertFilter) object;
            return this.zzazt.equals(nearbyAlertFilter.zzazt) && this.zzazx.equals(nearbyAlertFilter.zzazx) && this.zzazw.equals(nearbyAlertFilter.zzazw);
        }
        return false;
    }

    @Override // com.google.android.gms.location.places.zza
    public Set<String> getPlaceIds() {
        return this.zzazw;
    }

    public int hashCode() {
        return zzt.hashCode(this.zzazt, this.zzazx, this.zzazw);
    }

    public String toString() {
        zzt.zza zzt = zzt.zzt(this);
        if (!this.zzazt.isEmpty()) {
            zzt.zzg("types", this.zzazt);
        }
        if (!this.zzazw.isEmpty()) {
            zzt.zzg("placeIds", this.zzazw);
        }
        if (!this.zzazx.isEmpty()) {
            zzt.zzg("requestedUserDataTypes", this.zzazx);
        }
        return zzt.toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzd zzdVar = CREATOR;
        zzd.zza(this, parcel, flags);
    }
}
