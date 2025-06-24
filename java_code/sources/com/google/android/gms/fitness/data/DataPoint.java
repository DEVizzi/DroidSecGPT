package com.google.android.gms.fitness.data;

import android.content.Intent;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.Log;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.internal.zzlu;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;
/* loaded from: classes.dex */
public final class DataPoint implements SafeParcelable {
    public static final Parcelable.Creator<DataPoint> CREATOR = new zzd();
    private final int zzCY;
    private final DataSource zzajG;
    private long zzajV;
    private long zzajW;
    private final Value[] zzajX;
    private DataSource zzajY;
    private long zzajZ;
    private long zzaka;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DataPoint(int versionCode, DataSource dataSource, long timestampNanos, long startTimeNanos, Value[] values, DataSource originalDataSource, long rawTimestamp, long insertionTimeMillis) {
        this.zzCY = versionCode;
        this.zzajG = dataSource;
        this.zzajY = originalDataSource;
        this.zzajV = timestampNanos;
        this.zzajW = startTimeNanos;
        this.zzajX = values;
        this.zzajZ = rawTimestamp;
        this.zzaka = insertionTimeMillis;
    }

    private DataPoint(DataSource dataSource) {
        this.zzCY = 4;
        this.zzajG = (DataSource) zzu.zzb(dataSource, "Data source cannot be null");
        List<Field> fields = dataSource.getDataType().getFields();
        this.zzajX = new Value[fields.size()];
        int i = 0;
        Iterator<Field> it = fields.iterator();
        while (true) {
            int i2 = i;
            if (!it.hasNext()) {
                return;
            }
            this.zzajX[i2] = new Value(it.next().getFormat());
            i = i2 + 1;
        }
    }

    public DataPoint(DataSource dataSource, DataSource originalDataSource, RawDataPoint rawDataPoint) {
        this(4, dataSource, zza(Long.valueOf(rawDataPoint.zzajV), 0L), zza(Long.valueOf(rawDataPoint.zzajW), 0L), rawDataPoint.zzajX, originalDataSource, zza(Long.valueOf(rawDataPoint.zzajZ), 0L), zza(Long.valueOf(rawDataPoint.zzaka), 0L));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DataPoint(List<DataSource> dataSources, RawDataPoint rawDataPoint) {
        this(zza(dataSources, rawDataPoint.zzakH), zza(dataSources, rawDataPoint.zzakI), rawDataPoint);
    }

    public static DataPoint create(DataSource dataSource) {
        return new DataPoint(dataSource);
    }

    public static DataPoint extract(Intent intent) {
        if (intent == null) {
            return null;
        }
        return (DataPoint) com.google.android.gms.common.internal.safeparcel.zzc.zza(intent, "com.google.android.gms.fitness.EXTRA_DATA_POINT", CREATOR);
    }

    private static long zza(Long l, long j) {
        return l != null ? l.longValue() : j;
    }

    private static DataSource zza(List<DataSource> list, int i) {
        if (i < 0 || i >= list.size()) {
            return null;
        }
        return list.get(i);
    }

    private boolean zza(DataPoint dataPoint) {
        return com.google.android.gms.common.internal.zzt.equal(this.zzajG, dataPoint.zzajG) && this.zzajV == dataPoint.zzajV && this.zzajW == dataPoint.zzajW && Arrays.equals(this.zzajX, dataPoint.zzajX) && com.google.android.gms.common.internal.zzt.equal(this.zzajY, dataPoint.zzajY);
    }

    private void zzed(int i) {
        List<Field> fields = getDataType().getFields();
        int size = fields.size();
        zzu.zzb(i == size, "Attempting to insert %s values, but needed %s: %s", Integer.valueOf(i), Integer.valueOf(size), fields);
    }

    private boolean zzqt() {
        return getDataType() == DataType.TYPE_LOCATION_SAMPLE;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        return this == o || ((o instanceof DataPoint) && zza((DataPoint) o));
    }

    public DataSource getDataSource() {
        return this.zzajG;
    }

    public DataType getDataType() {
        return this.zzajG.getDataType();
    }

    public long getEndTime(TimeUnit timeUnit) {
        return timeUnit.convert(this.zzajV, TimeUnit.NANOSECONDS);
    }

    public DataSource getOriginalDataSource() {
        return this.zzajY;
    }

    public long getStartTime(TimeUnit timeUnit) {
        return timeUnit.convert(this.zzajW, TimeUnit.NANOSECONDS);
    }

    public long getTimestamp(TimeUnit timeUnit) {
        return timeUnit.convert(this.zzajV, TimeUnit.NANOSECONDS);
    }

    public long getTimestampNanos() {
        return this.zzajV;
    }

    public Value getValue(Field field) {
        return this.zzajX[getDataType().indexOf(field)];
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(this.zzajG, Long.valueOf(this.zzajV), Long.valueOf(this.zzajW));
    }

    public DataPoint setFloatValues(float... values) {
        zzed(values.length);
        for (int i = 0; i < values.length; i++) {
            this.zzajX[i].setFloat(values[i]);
        }
        return this;
    }

    public DataPoint setIntValues(int... values) {
        zzed(values.length);
        for (int i = 0; i < values.length; i++) {
            this.zzajX[i].setInt(values[i]);
        }
        return this;
    }

    public DataPoint setTimeInterval(long startTime, long endTime, TimeUnit timeUnit) {
        this.zzajW = timeUnit.toNanos(startTime);
        this.zzajV = timeUnit.toNanos(endTime);
        return this;
    }

    public DataPoint setTimestamp(long timestamp, TimeUnit timeUnit) {
        this.zzajV = timeUnit.toNanos(timestamp);
        if (zzqt() && zzlu.zza(timeUnit)) {
            Log.w("Fitness", "Storing location at more than millisecond granularity is not supported. Extra precision is lost as the value is converted to milliseconds.");
            this.zzajV = zzlu.zza(this.zzajV, TimeUnit.NANOSECONDS, TimeUnit.MILLISECONDS);
        }
        return this;
    }

    public String toString() {
        Object[] objArr = new Object[7];
        objArr[0] = Arrays.toString(this.zzajX);
        objArr[1] = Long.valueOf(this.zzajW);
        objArr[2] = Long.valueOf(this.zzajV);
        objArr[3] = Long.valueOf(this.zzajZ);
        objArr[4] = Long.valueOf(this.zzaka);
        objArr[5] = this.zzajG.toDebugString();
        objArr[6] = this.zzajY != null ? this.zzajY.toDebugString() : "N/A";
        return String.format("DataPoint{%s@[%s, %s,raw=%s,insert=%s](%s %s)}", objArr);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzd.zza(this, parcel, flags);
    }

    public Value[] zzqu() {
        return this.zzajX;
    }

    public long zzqv() {
        return this.zzajZ;
    }

    public long zzqw() {
        return this.zzaka;
    }

    public void zzqx() {
        zzu.zzb(getDataType().getName().equals(getDataSource().getDataType().getName()), "Conflicting data types found %s vs %s", getDataType(), getDataType());
        zzu.zzb(this.zzajV > 0, "Data point does not have the timestamp set: %s", this);
        zzu.zzb(this.zzajW <= this.zzajV, "Data point with start time greater than end time found: %s", this);
    }

    public long zzqy() {
        return this.zzajW;
    }
}
