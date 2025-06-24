package com.google.android.gms.location;

import android.os.Parcel;
import android.os.SystemClock;
import android.support.v7.internal.widget.ActivityChooserView;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
/* loaded from: classes.dex */
public final class LocationRequest implements SafeParcelable {
    public static final LocationRequestCreator CREATOR = new LocationRequestCreator();
    public static final int PRIORITY_BALANCED_POWER_ACCURACY = 102;
    public static final int PRIORITY_HIGH_ACCURACY = 100;
    public static final int PRIORITY_LOW_POWER = 104;
    public static final int PRIORITY_NO_POWER = 105;
    int mPriority;
    private final int zzCY;
    boolean zzamB;
    long zzaxU;
    long zzaxV;
    int zzaxW;
    float zzaxX;
    long zzaxY;
    long zzaxz;

    public LocationRequest() {
        this.zzCY = 1;
        this.mPriority = 102;
        this.zzaxU = 3600000L;
        this.zzaxV = 600000L;
        this.zzamB = false;
        this.zzaxz = Long.MAX_VALUE;
        this.zzaxW = ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        this.zzaxX = 0.0f;
        this.zzaxY = 0L;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LocationRequest(int versionCode, int priority, long interval, long fastestInterval, boolean explicitFastestInterval, long expireAt, int numUpdates, float smallestDisplacement, long maxWaitTime) {
        this.zzCY = versionCode;
        this.mPriority = priority;
        this.zzaxU = interval;
        this.zzaxV = fastestInterval;
        this.zzamB = explicitFastestInterval;
        this.zzaxz = expireAt;
        this.zzaxW = numUpdates;
        this.zzaxX = smallestDisplacement;
        this.zzaxY = maxWaitTime;
    }

    public static LocationRequest create() {
        return new LocationRequest();
    }

    private static void zzK(long j) {
        if (j < 0) {
            throw new IllegalArgumentException("invalid interval: " + j);
        }
    }

    private static void zzd(float f) {
        if (f < 0.0f) {
            throw new IllegalArgumentException("invalid displacement: " + f);
        }
    }

    private static void zzgu(int i) {
        switch (i) {
            case 100:
            case 102:
            case 104:
            case 105:
                return;
            case 101:
            case 103:
            default:
                throw new IllegalArgumentException("invalid quality: " + i);
        }
    }

    public static String zzgv(int i) {
        switch (i) {
            case 100:
                return "PRIORITY_HIGH_ACCURACY";
            case 101:
            case 103:
            default:
                return "???";
            case 102:
                return "PRIORITY_BALANCED_POWER_ACCURACY";
            case 104:
                return "PRIORITY_LOW_POWER";
            case 105:
                return "PRIORITY_NO_POWER";
        }
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object instanceof LocationRequest) {
            LocationRequest locationRequest = (LocationRequest) object;
            return this.mPriority == locationRequest.mPriority && this.zzaxU == locationRequest.zzaxU && this.zzaxV == locationRequest.zzaxV && this.zzamB == locationRequest.zzamB && this.zzaxz == locationRequest.zzaxz && this.zzaxW == locationRequest.zzaxW && this.zzaxX == locationRequest.zzaxX;
        }
        return false;
    }

    public long getExpirationTime() {
        return this.zzaxz;
    }

    public long getFastestInterval() {
        return this.zzaxV;
    }

    public long getInterval() {
        return this.zzaxU;
    }

    public long getMaxWaitTime() {
        long j = this.zzaxY;
        return j < this.zzaxU ? this.zzaxU : j;
    }

    public int getNumUpdates() {
        return this.zzaxW;
    }

    public int getPriority() {
        return this.mPriority;
    }

    public float getSmallestDisplacement() {
        return this.zzaxX;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return zzt.hashCode(Integer.valueOf(this.mPriority), Long.valueOf(this.zzaxU), Long.valueOf(this.zzaxV), Boolean.valueOf(this.zzamB), Long.valueOf(this.zzaxz), Integer.valueOf(this.zzaxW), Float.valueOf(this.zzaxX));
    }

    public LocationRequest setExpirationDuration(long millis) {
        long elapsedRealtime = SystemClock.elapsedRealtime();
        if (millis > Long.MAX_VALUE - elapsedRealtime) {
            this.zzaxz = Long.MAX_VALUE;
        } else {
            this.zzaxz = elapsedRealtime + millis;
        }
        if (this.zzaxz < 0) {
            this.zzaxz = 0L;
        }
        return this;
    }

    public LocationRequest setExpirationTime(long millis) {
        this.zzaxz = millis;
        if (this.zzaxz < 0) {
            this.zzaxz = 0L;
        }
        return this;
    }

    public LocationRequest setFastestInterval(long millis) {
        zzK(millis);
        this.zzamB = true;
        this.zzaxV = millis;
        return this;
    }

    public LocationRequest setInterval(long millis) {
        zzK(millis);
        this.zzaxU = millis;
        if (!this.zzamB) {
            this.zzaxV = (long) (this.zzaxU / 6.0d);
        }
        return this;
    }

    public LocationRequest setMaxWaitTime(long millis) {
        zzK(millis);
        this.zzaxY = millis;
        return this;
    }

    public LocationRequest setNumUpdates(int numUpdates) {
        if (numUpdates <= 0) {
            throw new IllegalArgumentException("invalid numUpdates: " + numUpdates);
        }
        this.zzaxW = numUpdates;
        return this;
    }

    public LocationRequest setPriority(int priority) {
        zzgu(priority);
        this.mPriority = priority;
        return this;
    }

    public LocationRequest setSmallestDisplacement(float smallestDisplacementMeters) {
        zzd(smallestDisplacementMeters);
        this.zzaxX = smallestDisplacementMeters;
        return this;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Request[").append(zzgv(this.mPriority));
        if (this.mPriority != 105) {
            sb.append(" requested=");
            sb.append(this.zzaxU + "ms");
        }
        sb.append(" fastest=");
        sb.append(this.zzaxV + "ms");
        if (this.zzaxY > this.zzaxU) {
            sb.append(" maxWait=");
            sb.append(this.zzaxY + "ms");
        }
        if (this.zzaxz != Long.MAX_VALUE) {
            sb.append(" expireIn=");
            sb.append((this.zzaxz - SystemClock.elapsedRealtime()) + "ms");
        }
        if (this.zzaxW != Integer.MAX_VALUE) {
            sb.append(" num=").append(this.zzaxW);
        }
        sb.append(']');
        return sb.toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        LocationRequestCreator.zza(this, parcel, flags);
    }
}
