package com.google.android.gms.location;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
/* loaded from: classes.dex */
public final class LocationSettingsRequest implements SafeParcelable {
    public static final Parcelable.Creator<LocationSettingsRequest> CREATOR = new zzg();
    private final int zzCY;
    private final List<LocationRequest> zzamw;
    private final boolean zzayb;
    private final boolean zzayc;
    private final boolean zzayd;

    /* loaded from: classes.dex */
    public static final class Builder {
        private final ArrayList<LocationRequest> zzaye = new ArrayList<>();
        private boolean zzayb = false;
        private boolean zzayc = false;
        private boolean zzayd = false;

        public Builder addAllLocationRequests(Collection<LocationRequest> requests) {
            this.zzaye.addAll(requests);
            return this;
        }

        public Builder addLocationRequest(LocationRequest request) {
            this.zzaye.add(request);
            return this;
        }

        public LocationSettingsRequest build() {
            return new LocationSettingsRequest(this.zzaye, this.zzayb, this.zzayc, this.zzayd);
        }

        public Builder setAlwaysShow(boolean show) {
            this.zzayb = show;
            return this;
        }

        public Builder setNeedBle(boolean needBle) {
            this.zzayc = needBle;
            return this;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LocationSettingsRequest(int version, List<LocationRequest> locationRequests, boolean alwaysShow, boolean needBle, boolean optInUserLocationReporting) {
        this.zzCY = version;
        this.zzamw = locationRequests;
        this.zzayb = alwaysShow;
        this.zzayc = needBle;
        this.zzayd = optInUserLocationReporting;
    }

    private LocationSettingsRequest(List<LocationRequest> locationRequests, boolean alwaysShow, boolean needBle, boolean optInUserLocationReporting) {
        this(2, locationRequests, alwaysShow, needBle, optInUserLocationReporting);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzg.zza(this, dest, flags);
    }

    public List<LocationRequest> zzrj() {
        return Collections.unmodifiableList(this.zzamw);
    }

    public boolean zzup() {
        return this.zzayb;
    }

    public boolean zzuq() {
        return this.zzayc;
    }

    public boolean zzur() {
        return this.zzayd;
    }
}
