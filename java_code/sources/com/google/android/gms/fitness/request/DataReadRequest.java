package com.google.android.gms.fitness.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.fitness.data.Bucket;
import com.google.android.gms.fitness.data.DataSource;
import com.google.android.gms.fitness.data.DataType;
import com.google.android.gms.fitness.data.Device;
import com.google.android.gms.internal.zzmf;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
/* loaded from: classes.dex */
public class DataReadRequest implements SafeParcelable {
    public static final Parcelable.Creator<DataReadRequest> CREATOR = new zzf();
    public static final int NO_LIMIT = 0;
    private final int zzCY;
    private final long zzKT;
    private final String zzMZ;
    private final long zzajH;
    private final List<DataType> zzajQ;
    private final int zzajT;
    private final List<DataSource> zzalP;
    private final List<DataType> zzalU;
    private final List<DataSource> zzalV;
    private final long zzalW;
    private final DataSource zzalX;
    private final int zzalY;
    private final boolean zzalZ;
    private final boolean zzama;
    private final zzmf zzamb;
    private final List<Device> zzamc;

    /* loaded from: classes.dex */
    public static class Builder {
        private long zzKT;
        private long zzajH;
        private DataSource zzalX;
        private List<DataType> zzajQ = new ArrayList();
        private List<DataSource> zzalP = new ArrayList();
        private List<DataType> zzalU = new ArrayList();
        private List<DataSource> zzalV = new ArrayList();
        private int zzajT = 0;
        private long zzalW = 0;
        private int zzalY = 0;
        private boolean zzalZ = false;
        private boolean zzama = false;
        private List<Device> zzamc = new ArrayList();

        public Builder aggregate(DataSource dataSource, DataType outputDataType) {
            com.google.android.gms.common.internal.zzu.zzb(dataSource, "Attempting to add a null data source");
            com.google.android.gms.common.internal.zzu.zza(!this.zzalP.contains(dataSource), "Cannot add the same data source for aggregated and detailed");
            DataType dataType = dataSource.getDataType();
            com.google.android.gms.common.internal.zzu.zzb(DataType.AGGREGATE_INPUT_TYPES.contains(dataType), "Unsupported input data type specified for aggregation: %s", dataType);
            com.google.android.gms.common.internal.zzu.zzb(DataType.getAggregatesForInput(dataType).contains(outputDataType), "Invalid output aggregate data type specified: %s -> %s", dataType, outputDataType);
            if (!this.zzalV.contains(dataSource)) {
                this.zzalV.add(dataSource);
            }
            return this;
        }

        public Builder aggregate(DataType inputDataType, DataType outputDataType) {
            com.google.android.gms.common.internal.zzu.zzb(inputDataType, "Attempting to use a null data type");
            com.google.android.gms.common.internal.zzu.zza(!this.zzajQ.contains(inputDataType), "Cannot add the same data type as aggregated and detailed");
            com.google.android.gms.common.internal.zzu.zzb(DataType.AGGREGATE_INPUT_TYPES.contains(inputDataType), "Unsupported input data type specified for aggregation: %s", inputDataType);
            com.google.android.gms.common.internal.zzu.zzb(DataType.getAggregatesForInput(inputDataType).contains(outputDataType), "Invalid output aggregate data type specified: %s -> %s", inputDataType, outputDataType);
            if (!this.zzalU.contains(inputDataType)) {
                this.zzalU.add(inputDataType);
            }
            return this;
        }

        public Builder bucketByActivitySegment(int minDuration, TimeUnit timeUnit) {
            com.google.android.gms.common.internal.zzu.zzb(this.zzajT == 0, "Bucketing strategy already set to %s", Integer.valueOf(this.zzajT));
            com.google.android.gms.common.internal.zzu.zzb(minDuration > 0, "Must specify a valid minimum duration for an activity segment: %d", Integer.valueOf(minDuration));
            this.zzajT = 4;
            this.zzalW = timeUnit.toMillis(minDuration);
            return this;
        }

        public Builder bucketByActivitySegment(int minDuration, TimeUnit timeUnit, DataSource activityDataSource) {
            com.google.android.gms.common.internal.zzu.zzb(this.zzajT == 0, "Bucketing strategy already set to %s", Integer.valueOf(this.zzajT));
            com.google.android.gms.common.internal.zzu.zzb(minDuration > 0, "Must specify a valid minimum duration for an activity segment: %d", Integer.valueOf(minDuration));
            com.google.android.gms.common.internal.zzu.zzb(activityDataSource != null, "Invalid activity data source specified");
            com.google.android.gms.common.internal.zzu.zzb(activityDataSource.getDataType().equals(DataType.TYPE_ACTIVITY_SEGMENT), "Invalid activity data source specified: %s", activityDataSource);
            this.zzalX = activityDataSource;
            this.zzajT = 4;
            this.zzalW = timeUnit.toMillis(minDuration);
            return this;
        }

        public Builder bucketByActivityType(int minDuration, TimeUnit timeUnit) {
            com.google.android.gms.common.internal.zzu.zzb(this.zzajT == 0, "Bucketing strategy already set to %s", Integer.valueOf(this.zzajT));
            com.google.android.gms.common.internal.zzu.zzb(minDuration > 0, "Must specify a valid minimum duration for an activity segment: %d", Integer.valueOf(minDuration));
            this.zzajT = 3;
            this.zzalW = timeUnit.toMillis(minDuration);
            return this;
        }

        public Builder bucketByActivityType(int minDuration, TimeUnit timeUnit, DataSource activityDataSource) {
            com.google.android.gms.common.internal.zzu.zzb(this.zzajT == 0, "Bucketing strategy already set to %s", Integer.valueOf(this.zzajT));
            com.google.android.gms.common.internal.zzu.zzb(minDuration > 0, "Must specify a valid minimum duration for an activity segment: %d", Integer.valueOf(minDuration));
            com.google.android.gms.common.internal.zzu.zzb(activityDataSource != null, "Invalid activity data source specified");
            com.google.android.gms.common.internal.zzu.zzb(activityDataSource.getDataType().equals(DataType.TYPE_ACTIVITY_SEGMENT), "Invalid activity data source specified: %s", activityDataSource);
            this.zzalX = activityDataSource;
            this.zzajT = 3;
            this.zzalW = timeUnit.toMillis(minDuration);
            return this;
        }

        public Builder bucketBySession(int minDuration, TimeUnit timeUnit) {
            com.google.android.gms.common.internal.zzu.zzb(this.zzajT == 0, "Bucketing strategy already set to %s", Integer.valueOf(this.zzajT));
            com.google.android.gms.common.internal.zzu.zzb(minDuration > 0, "Must specify a valid minimum duration for an activity segment: %d", Integer.valueOf(minDuration));
            this.zzajT = 2;
            this.zzalW = timeUnit.toMillis(minDuration);
            return this;
        }

        public Builder bucketByTime(int duration, TimeUnit timeUnit) {
            com.google.android.gms.common.internal.zzu.zzb(this.zzajT == 0, "Bucketing strategy already set to %s", Integer.valueOf(this.zzajT));
            com.google.android.gms.common.internal.zzu.zzb(duration > 0, "Must specify a valid minimum duration for an activity segment: %d", Integer.valueOf(duration));
            this.zzajT = 1;
            this.zzalW = timeUnit.toMillis(duration);
            return this;
        }

        public DataReadRequest build() {
            boolean z = true;
            com.google.android.gms.common.internal.zzu.zza((this.zzalP.isEmpty() && this.zzajQ.isEmpty() && this.zzalV.isEmpty() && this.zzalU.isEmpty()) ? false : true, "Must add at least one data source (aggregated or detailed)");
            com.google.android.gms.common.internal.zzu.zza(this.zzKT > 0, "Invalid start time: %s", Long.valueOf(this.zzKT));
            com.google.android.gms.common.internal.zzu.zza(this.zzajH > 0 && this.zzajH > this.zzKT, "Invalid end time: %s", Long.valueOf(this.zzajH));
            boolean z2 = this.zzalV.isEmpty() && this.zzalU.isEmpty();
            if ((!z2 || this.zzajT != 0) && (z2 || this.zzajT == 0)) {
                z = false;
            }
            com.google.android.gms.common.internal.zzu.zza(z, "Must specify a valid bucketing strategy while requesting aggregation");
            return new DataReadRequest(this);
        }

        public Builder enableServerQueries() {
            this.zzama = true;
            return this;
        }

        public Builder read(DataSource dataSource) {
            com.google.android.gms.common.internal.zzu.zzb(dataSource, "Attempting to add a null data source");
            com.google.android.gms.common.internal.zzu.zzb(!this.zzalV.contains(dataSource), "Cannot add the same data source as aggregated and detailed");
            if (!this.zzalP.contains(dataSource)) {
                this.zzalP.add(dataSource);
            }
            return this;
        }

        public Builder read(DataType dataType) {
            com.google.android.gms.common.internal.zzu.zzb(dataType, "Attempting to use a null data type");
            com.google.android.gms.common.internal.zzu.zza(!this.zzalU.contains(dataType), "Cannot add the same data type as aggregated and detailed");
            if (!this.zzajQ.contains(dataType)) {
                this.zzajQ.add(dataType);
            }
            return this;
        }

        public Builder setLimit(int limit) {
            com.google.android.gms.common.internal.zzu.zzb(limit > 0, "Invalid limit %d is specified", Integer.valueOf(limit));
            this.zzalY = limit;
            return this;
        }

        public Builder setTimeRange(long start, long end, TimeUnit timeUnit) {
            this.zzKT = timeUnit.toMillis(start);
            this.zzajH = timeUnit.toMillis(end);
            return this;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DataReadRequest(int versionCode, List<DataType> dataTypes, List<DataSource> dataSources, long startTimeMillis, long endTimeMillis, List<DataType> aggregatedDataTypes, List<DataSource> aggregatedDataSources, int bucketType, long bucketDurationMillis, DataSource activityDataSource, int limit, boolean flushBeforeRead, boolean serverQueriesEnabled, IBinder callback, String packageName, List<Device> filteredDevices) {
        this.zzCY = versionCode;
        this.zzajQ = Collections.unmodifiableList(dataTypes);
        this.zzalP = Collections.unmodifiableList(dataSources);
        this.zzKT = startTimeMillis;
        this.zzajH = endTimeMillis;
        this.zzalU = Collections.unmodifiableList(aggregatedDataTypes);
        this.zzalV = Collections.unmodifiableList(aggregatedDataSources);
        this.zzajT = bucketType;
        this.zzalW = bucketDurationMillis;
        this.zzalX = activityDataSource;
        this.zzalY = limit;
        this.zzalZ = flushBeforeRead;
        this.zzama = serverQueriesEnabled;
        this.zzamb = callback == null ? null : zzmf.zza.zzbq(callback);
        this.zzMZ = packageName;
        this.zzamc = filteredDevices == null ? Collections.EMPTY_LIST : filteredDevices;
    }

    private DataReadRequest(Builder builder) {
        this(builder.zzajQ, builder.zzalP, builder.zzKT, builder.zzajH, builder.zzalU, builder.zzalV, builder.zzajT, builder.zzalW, builder.zzalX, builder.zzalY, builder.zzalZ, builder.zzama, null, null, builder.zzamc);
    }

    public DataReadRequest(DataReadRequest request, zzmf callback, String packageName) {
        this(request.zzajQ, request.zzalP, request.zzKT, request.zzajH, request.zzalU, request.zzalV, request.zzajT, request.zzalW, request.zzalX, request.zzalY, request.zzalZ, request.zzama, callback, packageName, request.zzamc);
    }

    public DataReadRequest(List<DataType> dataTypes, List<DataSource> dataSources, long startTimeMillis, long endTimeMillis, List<DataType> aggregatedDataTypes, List<DataSource> aggregatedDataSources, int bucketType, long bucketDurationMillis, DataSource activityDataSource, int limit, boolean flushBeforeRead, boolean serverQueriesEnabled, zzmf callback, String packageName, List<Device> filteredDevices) {
        this.zzCY = 4;
        this.zzajQ = Collections.unmodifiableList(dataTypes);
        this.zzalP = Collections.unmodifiableList(dataSources);
        this.zzKT = startTimeMillis;
        this.zzajH = endTimeMillis;
        this.zzalU = Collections.unmodifiableList(aggregatedDataTypes);
        this.zzalV = Collections.unmodifiableList(aggregatedDataSources);
        this.zzajT = bucketType;
        this.zzalW = bucketDurationMillis;
        this.zzalX = activityDataSource;
        this.zzalY = limit;
        this.zzalZ = flushBeforeRead;
        this.zzama = serverQueriesEnabled;
        this.zzamb = callback;
        this.zzMZ = packageName;
        this.zzamc = filteredDevices;
    }

    private boolean zzb(DataReadRequest dataReadRequest) {
        return this.zzajQ.equals(dataReadRequest.zzajQ) && this.zzalP.equals(dataReadRequest.zzalP) && this.zzKT == dataReadRequest.zzKT && this.zzajH == dataReadRequest.zzajH && this.zzajT == dataReadRequest.zzajT && this.zzalV.equals(dataReadRequest.zzalV) && this.zzalU.equals(dataReadRequest.zzalU) && com.google.android.gms.common.internal.zzt.equal(this.zzalX, dataReadRequest.zzalX) && this.zzalW == dataReadRequest.zzalW && this.zzama == dataReadRequest.zzama;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object that) {
        return this == that || ((that instanceof DataReadRequest) && zzb((DataReadRequest) that));
    }

    public DataSource getActivityDataSource() {
        return this.zzalX;
    }

    public List<DataSource> getAggregatedDataSources() {
        return this.zzalV;
    }

    public List<DataType> getAggregatedDataTypes() {
        return this.zzalU;
    }

    public long getBucketDuration(TimeUnit timeUnit) {
        return timeUnit.convert(this.zzalW, TimeUnit.MILLISECONDS);
    }

    public int getBucketType() {
        return this.zzajT;
    }

    public List<DataSource> getDataSources() {
        return this.zzalP;
    }

    public List<DataType> getDataTypes() {
        return this.zzajQ;
    }

    public long getEndTime(TimeUnit timeUnit) {
        return timeUnit.convert(this.zzajH, TimeUnit.MILLISECONDS);
    }

    public int getLimit() {
        return this.zzalY;
    }

    public String getPackageName() {
        return this.zzMZ;
    }

    public long getStartTime(TimeUnit timeUnit) {
        return timeUnit.convert(this.zzKT, TimeUnit.MILLISECONDS);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(Integer.valueOf(this.zzajT), Long.valueOf(this.zzKT), Long.valueOf(this.zzajH));
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("DataReadRequest{");
        if (!this.zzajQ.isEmpty()) {
            for (DataType dataType : this.zzajQ) {
                sb.append(dataType.zzqD()).append(" ");
            }
        }
        if (!this.zzalP.isEmpty()) {
            for (DataSource dataSource : this.zzalP) {
                sb.append(dataSource.toDebugString()).append(" ");
            }
        }
        if (this.zzajT != 0) {
            sb.append("bucket by ").append(Bucket.zzeb(this.zzajT));
            if (this.zzalW > 0) {
                sb.append(" >").append(this.zzalW).append("ms");
            }
            sb.append(": ");
        }
        if (!this.zzalU.isEmpty()) {
            for (DataType dataType2 : this.zzalU) {
                sb.append(dataType2.zzqD()).append(" ");
            }
        }
        if (!this.zzalV.isEmpty()) {
            for (DataSource dataSource2 : this.zzalV) {
                sb.append(dataSource2.toDebugString()).append(" ");
            }
        }
        sb.append(String.format("(%tF %tT - %tF %tT)", Long.valueOf(this.zzKT), Long.valueOf(this.zzKT), Long.valueOf(this.zzajH), Long.valueOf(this.zzajH)));
        if (this.zzalX != null) {
            sb.append("activities: ").append(this.zzalX.toDebugString());
        }
        if (this.zzama) {
            sb.append(" +server");
        }
        sb.append("}");
        return sb.toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzf.zza(this, dest, flags);
    }

    public long zzkt() {
        return this.zzKT;
    }

    public IBinder zzqU() {
        if (this.zzamb == null) {
            return null;
        }
        return this.zzamb.asBinder();
    }

    public boolean zzqZ() {
        return this.zzama;
    }

    public long zzqs() {
        return this.zzajH;
    }

    public boolean zzra() {
        return this.zzalZ;
    }

    public long zzrb() {
        return this.zzalW;
    }

    public List<Device> zzrc() {
        return this.zzamc;
    }
}
