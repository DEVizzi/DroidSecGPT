package com.google.android.gms.fitness.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.Log;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.fitness.data.DataPoint;
import com.google.android.gms.fitness.data.DataSet;
import com.google.android.gms.fitness.data.DataSource;
import com.google.android.gms.fitness.data.Session;
import com.google.android.gms.internal.zzlu;
import com.google.android.gms.internal.zzmu;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
/* loaded from: classes.dex */
public class SessionInsertRequest implements SafeParcelable {
    public static final Parcelable.Creator<SessionInsertRequest> CREATOR = new zzu();
    private final int zzCY;
    private final String zzMZ;
    private final Session zzajJ;
    private final List<DataSet> zzajS;
    private final zzmu zzalN;
    private final List<DataPoint> zzamC;

    /* loaded from: classes.dex */
    public static class Builder {
        private Session zzajJ;
        private List<DataSet> zzajS = new ArrayList();
        private List<DataPoint> zzamC = new ArrayList();
        private List<DataSource> zzamD = new ArrayList();

        private void zzd(DataPoint dataPoint) {
            zzf(dataPoint);
            zze(dataPoint);
        }

        private void zze(DataPoint dataPoint) {
            long startTime = this.zzajJ.getStartTime(TimeUnit.NANOSECONDS);
            long endTime = this.zzajJ.getEndTime(TimeUnit.NANOSECONDS);
            long startTime2 = dataPoint.getStartTime(TimeUnit.NANOSECONDS);
            long endTime2 = dataPoint.getEndTime(TimeUnit.NANOSECONDS);
            if (startTime2 == 0 || endTime2 == 0) {
                return;
            }
            TimeUnit timeUnit = TimeUnit.MILLISECONDS;
            if (endTime2 > endTime) {
                endTime2 = zzlu.zza(endTime2, TimeUnit.NANOSECONDS, timeUnit);
            }
            com.google.android.gms.common.internal.zzu.zza(startTime2 >= startTime && endTime2 <= endTime, "Data point %s has start and end times outside session interval [%d, %d]", dataPoint, Long.valueOf(startTime), Long.valueOf(endTime));
            if (endTime2 != dataPoint.getEndTime(TimeUnit.NANOSECONDS)) {
                Log.w("Fitness", String.format("Data point end time [%d] is truncated to [%d] to match the precision [%s] of the session start and end time", Long.valueOf(dataPoint.getEndTime(TimeUnit.NANOSECONDS)), Long.valueOf(endTime2), timeUnit));
                dataPoint.setTimeInterval(startTime2, endTime2, TimeUnit.NANOSECONDS);
            }
        }

        private void zzf(DataPoint dataPoint) {
            long startTime = this.zzajJ.getStartTime(TimeUnit.NANOSECONDS);
            long endTime = this.zzajJ.getEndTime(TimeUnit.NANOSECONDS);
            long timestamp = dataPoint.getTimestamp(TimeUnit.NANOSECONDS);
            if (timestamp != 0) {
                TimeUnit timeUnit = TimeUnit.MILLISECONDS;
                if (timestamp < startTime || timestamp > endTime) {
                    timestamp = zzlu.zza(timestamp, TimeUnit.NANOSECONDS, timeUnit);
                }
                com.google.android.gms.common.internal.zzu.zza(timestamp >= startTime && timestamp <= endTime, "Data point %s has time stamp outside session interval [%d, %d]", dataPoint, Long.valueOf(startTime), Long.valueOf(endTime));
                if (dataPoint.getTimestamp(TimeUnit.NANOSECONDS) != timestamp) {
                    Log.w("Fitness", String.format("Data point timestamp [%d] is truncated to [%d] to match the precision [%s] of the session start and end time", Long.valueOf(dataPoint.getTimestamp(TimeUnit.NANOSECONDS)), Long.valueOf(timestamp), timeUnit));
                    dataPoint.setTimestamp(timestamp, TimeUnit.NANOSECONDS);
                }
            }
        }

        private void zzrn() {
            for (DataSet dataSet : this.zzajS) {
                for (DataPoint dataPoint : dataSet.getDataPoints()) {
                    zzd(dataPoint);
                }
            }
            for (DataPoint dataPoint2 : this.zzamC) {
                zzd(dataPoint2);
            }
        }

        public Builder addAggregateDataPoint(DataPoint aggregateDataPoint) {
            com.google.android.gms.common.internal.zzu.zzb(aggregateDataPoint != null, "Must specify a valid aggregate data point.");
            long startTime = aggregateDataPoint.getStartTime(TimeUnit.NANOSECONDS);
            com.google.android.gms.common.internal.zzu.zzb(startTime > 0 && aggregateDataPoint.getEndTime(TimeUnit.NANOSECONDS) > startTime, "Aggregate data point should have valid start and end times: %s", aggregateDataPoint);
            DataSource dataSource = aggregateDataPoint.getDataSource();
            com.google.android.gms.common.internal.zzu.zza(!this.zzamD.contains(dataSource), "Data set/Aggregate data point for this data source %s is already added.", dataSource);
            this.zzamD.add(dataSource);
            this.zzamC.add(aggregateDataPoint);
            return this;
        }

        public Builder addDataSet(DataSet dataSet) {
            com.google.android.gms.common.internal.zzu.zzb(dataSet != null, "Must specify a valid data set.");
            DataSource dataSource = dataSet.getDataSource();
            com.google.android.gms.common.internal.zzu.zza(!this.zzamD.contains(dataSource), "Data set for this data source %s is already added.", dataSource);
            com.google.android.gms.common.internal.zzu.zzb(dataSet.getDataPoints().isEmpty() ? false : true, "No data points specified in the input data set.");
            this.zzamD.add(dataSource);
            this.zzajS.add(dataSet);
            return this;
        }

        public SessionInsertRequest build() {
            com.google.android.gms.common.internal.zzu.zza(this.zzajJ != null, "Must specify a valid session.");
            com.google.android.gms.common.internal.zzu.zza(this.zzajJ.getEndTime(TimeUnit.MILLISECONDS) != 0, "Must specify a valid end time, cannot insert a continuing session.");
            zzrn();
            return new SessionInsertRequest(this);
        }

        public Builder setSession(Session session) {
            this.zzajJ = session;
            return this;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SessionInsertRequest(int versionCode, Session session, List<DataSet> dataSets, List<DataPoint> aggregateDataPoints, IBinder callback, String packageName) {
        this.zzCY = versionCode;
        this.zzajJ = session;
        this.zzajS = Collections.unmodifiableList(dataSets);
        this.zzamC = Collections.unmodifiableList(aggregateDataPoints);
        this.zzalN = callback == null ? null : zzmu.zza.zzbF(callback);
        this.zzMZ = packageName;
    }

    public SessionInsertRequest(Session session, List<DataSet> dataSets, List<DataPoint> aggregateDataPoints, zzmu callback, String packageName) {
        this.zzCY = 2;
        this.zzajJ = session;
        this.zzajS = Collections.unmodifiableList(dataSets);
        this.zzamC = Collections.unmodifiableList(aggregateDataPoints);
        this.zzalN = callback;
        this.zzMZ = packageName;
    }

    private SessionInsertRequest(Builder builder) {
        this(builder.zzajJ, builder.zzajS, builder.zzamC, null, null);
    }

    public SessionInsertRequest(SessionInsertRequest request, zzmu callback, String packageName) {
        this(request.zzajJ, request.zzajS, request.zzamC, callback, packageName);
    }

    private boolean zzb(SessionInsertRequest sessionInsertRequest) {
        return com.google.android.gms.common.internal.zzt.equal(this.zzajJ, sessionInsertRequest.zzajJ) && com.google.android.gms.common.internal.zzt.equal(this.zzajS, sessionInsertRequest.zzajS) && com.google.android.gms.common.internal.zzt.equal(this.zzamC, sessionInsertRequest.zzamC);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        return o == this || ((o instanceof SessionInsertRequest) && zzb((SessionInsertRequest) o));
    }

    public List<DataPoint> getAggregateDataPoints() {
        return this.zzamC;
    }

    public List<DataSet> getDataSets() {
        return this.zzajS;
    }

    public String getPackageName() {
        return this.zzMZ;
    }

    public Session getSession() {
        return this.zzajJ;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(this.zzajJ, this.zzajS, this.zzamC);
    }

    public String toString() {
        return com.google.android.gms.common.internal.zzt.zzt(this).zzg("session", this.zzajJ).zzg("dataSets", this.zzajS).zzg("aggregateDataPoints", this.zzamC).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzu.zza(this, dest, flags);
    }

    public IBinder zzqU() {
        if (this.zzalN == null) {
            return null;
        }
        return this.zzalN.asBinder();
    }
}
