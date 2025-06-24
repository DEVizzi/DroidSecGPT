package com.google.android.gms.fitness.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.fitness.FitnessActivities;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;
/* loaded from: classes.dex */
public class Bucket implements SafeParcelable {
    public static final Parcelable.Creator<Bucket> CREATOR = new zzc();
    public static final int TYPE_ACTIVITY_SEGMENT = 4;
    public static final int TYPE_ACTIVITY_TYPE = 3;
    public static final int TYPE_SESSION = 2;
    public static final int TYPE_TIME = 1;
    private final int zzCY;
    private final long zzKT;
    private final long zzajH;
    private final Session zzajJ;
    private final int zzajR;
    private final List<DataSet> zzajS;
    private final int zzajT;
    private boolean zzajU;

    /* JADX INFO: Access modifiers changed from: package-private */
    public Bucket(int versionCode, long startTimeMillis, long endTimeMillis, Session session, int activityType, List<DataSet> dataSets, int bucketType, boolean serverHasMoreData) {
        this.zzajU = false;
        this.zzCY = versionCode;
        this.zzKT = startTimeMillis;
        this.zzajH = endTimeMillis;
        this.zzajJ = session;
        this.zzajR = activityType;
        this.zzajS = dataSets;
        this.zzajT = bucketType;
        this.zzajU = serverHasMoreData;
    }

    public Bucket(RawBucket bucket, List<DataSource> uniqueDataSources) {
        this(2, bucket.zzKT, bucket.zzajH, bucket.zzajJ, bucket.zzakG, zza(bucket.zzajS, uniqueDataSources), bucket.zzajT, bucket.zzajU);
    }

    private static List<DataSet> zza(Collection<RawDataSet> collection, List<DataSource> list) {
        ArrayList arrayList = new ArrayList(collection.size());
        for (RawDataSet rawDataSet : collection) {
            arrayList.add(new DataSet(rawDataSet, list));
        }
        return arrayList;
    }

    private boolean zza(Bucket bucket) {
        return this.zzKT == bucket.zzKT && this.zzajH == bucket.zzajH && this.zzajR == bucket.zzajR && com.google.android.gms.common.internal.zzt.equal(this.zzajS, bucket.zzajS) && this.zzajT == bucket.zzajT && this.zzajU == bucket.zzajU;
    }

    public static String zzeb(int i) {
        switch (i) {
            case 0:
                return "unknown";
            case 1:
                return "time";
            case 2:
                return "session";
            case 3:
                return "type";
            case 4:
                return "segment";
            default:
                return "bug";
        }
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        return o == this || ((o instanceof Bucket) && zza((Bucket) o));
    }

    public String getActivity() {
        return FitnessActivities.getName(this.zzajR);
    }

    public int getBucketType() {
        return this.zzajT;
    }

    public DataSet getDataSet(DataType dataType) {
        for (DataSet dataSet : this.zzajS) {
            if (dataSet.getDataType().equals(dataType)) {
                return dataSet;
            }
        }
        return null;
    }

    public List<DataSet> getDataSets() {
        return this.zzajS;
    }

    public long getEndTime(TimeUnit timeUnit) {
        return timeUnit.convert(this.zzajH, TimeUnit.MILLISECONDS);
    }

    public Session getSession() {
        return this.zzajJ;
    }

    public long getStartTime(TimeUnit timeUnit) {
        return timeUnit.convert(this.zzKT, TimeUnit.MILLISECONDS);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(Long.valueOf(this.zzKT), Long.valueOf(this.zzajH), Integer.valueOf(this.zzajR), Integer.valueOf(this.zzajT));
    }

    public String toString() {
        return com.google.android.gms.common.internal.zzt.zzt(this).zzg("startTime", Long.valueOf(this.zzKT)).zzg("endTime", Long.valueOf(this.zzajH)).zzg("activity", Integer.valueOf(this.zzajR)).zzg("dataSets", this.zzajS).zzg("bucketType", zzeb(this.zzajT)).zzg("serverHasMoreData", Boolean.valueOf(this.zzajU)).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzc.zza(this, dest, flags);
    }

    public boolean zzb(Bucket bucket) {
        return this.zzKT == bucket.zzKT && this.zzajH == bucket.zzajH && this.zzajR == bucket.zzajR && this.zzajT == bucket.zzajT;
    }

    public long zzkt() {
        return this.zzKT;
    }

    public int zzqq() {
        return this.zzajR;
    }

    public boolean zzqr() {
        if (this.zzajU) {
            return true;
        }
        for (DataSet dataSet : this.zzajS) {
            if (dataSet.zzqr()) {
                return true;
            }
        }
        return false;
    }

    public long zzqs() {
        return this.zzajH;
    }
}
