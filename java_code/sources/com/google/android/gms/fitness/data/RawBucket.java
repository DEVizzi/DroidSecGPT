package com.google.android.gms.fitness.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
/* loaded from: classes.dex */
public final class RawBucket implements SafeParcelable {
    public static final Parcelable.Creator<RawBucket> CREATOR = new zzm();
    final int zzCY;
    public final long zzKT;
    public final long zzajH;
    public final Session zzajJ;
    public final List<RawDataSet> zzajS;
    public final int zzajT;
    public final boolean zzajU;
    public final int zzakG;

    public RawBucket(int versionCode, long startTimeMillis, long endTimeMillis, Session session, int activity, List<RawDataSet> dataSets, int bucketType, boolean serverHasMoreData) {
        this.zzCY = versionCode;
        this.zzKT = startTimeMillis;
        this.zzajH = endTimeMillis;
        this.zzajJ = session;
        this.zzakG = activity;
        this.zzajS = dataSets;
        this.zzajT = bucketType;
        this.zzajU = serverHasMoreData;
    }

    public RawBucket(Bucket bucket, List<DataSource> uniqueDataSources, List<DataType> uniqueDataTypes) {
        this.zzCY = 2;
        this.zzKT = bucket.getStartTime(TimeUnit.MILLISECONDS);
        this.zzajH = bucket.getEndTime(TimeUnit.MILLISECONDS);
        this.zzajJ = bucket.getSession();
        this.zzakG = bucket.zzqq();
        this.zzajT = bucket.getBucketType();
        this.zzajU = bucket.zzqr();
        List<DataSet> dataSets = bucket.getDataSets();
        this.zzajS = new ArrayList(dataSets.size());
        for (DataSet dataSet : dataSets) {
            this.zzajS.add(new RawDataSet(dataSet, uniqueDataSources, uniqueDataTypes));
        }
    }

    private boolean zza(RawBucket rawBucket) {
        return this.zzKT == rawBucket.zzKT && this.zzajH == rawBucket.zzajH && this.zzakG == rawBucket.zzakG && com.google.android.gms.common.internal.zzt.equal(this.zzajS, rawBucket.zzajS) && this.zzajT == rawBucket.zzajT && this.zzajU == rawBucket.zzajU;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        return this == o || ((o instanceof RawBucket) && zza((RawBucket) o));
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(Long.valueOf(this.zzKT), Long.valueOf(this.zzajH), Integer.valueOf(this.zzajT));
    }

    public String toString() {
        return com.google.android.gms.common.internal.zzt.zzt(this).zzg("startTime", Long.valueOf(this.zzKT)).zzg("endTime", Long.valueOf(this.zzajH)).zzg("activity", Integer.valueOf(this.zzakG)).zzg("dataSets", this.zzajS).zzg("bucketType", Integer.valueOf(this.zzajT)).zzg("serverHasMoreData", Boolean.valueOf(this.zzajU)).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzm.zza(this, parcel, flags);
    }
}
