package com.google.android.gms.fitness.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.fitness.data.DataSource;
import com.google.android.gms.fitness.data.DataType;
import com.google.android.gms.fitness.data.Session;
import com.google.android.gms.internal.zzmu;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
/* loaded from: classes.dex */
public class DataDeleteRequest implements SafeParcelable {
    public static final Parcelable.Creator<DataDeleteRequest> CREATOR = new zzd();
    private final int zzCY;
    private final long zzKT;
    private final String zzMZ;
    private final long zzajH;
    private final List<DataType> zzajQ;
    private final zzmu zzalN;
    private final List<DataSource> zzalP;
    private final List<Session> zzalQ;
    private final boolean zzalR;
    private final boolean zzalS;

    /* loaded from: classes.dex */
    public static class Builder {
        private long zzKT;
        private long zzajH;
        private List<DataSource> zzalP = new ArrayList();
        private List<DataType> zzajQ = new ArrayList();
        private List<Session> zzalQ = new ArrayList();
        private boolean zzalR = false;
        private boolean zzalS = false;

        private void zzqX() {
            if (this.zzalQ.isEmpty()) {
                return;
            }
            for (Session session : this.zzalQ) {
                com.google.android.gms.common.internal.zzu.zza(session.getStartTime(TimeUnit.MILLISECONDS) >= this.zzKT && session.getEndTime(TimeUnit.MILLISECONDS) <= this.zzajH, "Session %s is outside the time interval [%d, %d]", session, Long.valueOf(this.zzKT), Long.valueOf(this.zzajH));
            }
        }

        public Builder addDataSource(DataSource dataSource) {
            com.google.android.gms.common.internal.zzu.zzb(!this.zzalR, "All data is already marked for deletion");
            com.google.android.gms.common.internal.zzu.zzb(dataSource != null, "Must specify a valid data source");
            if (!this.zzalP.contains(dataSource)) {
                this.zzalP.add(dataSource);
            }
            return this;
        }

        public Builder addDataType(DataType dataType) {
            com.google.android.gms.common.internal.zzu.zzb(!this.zzalR, "All data is already marked for deletion");
            com.google.android.gms.common.internal.zzu.zzb(dataType != null, "Must specify a valid data type");
            if (!this.zzajQ.contains(dataType)) {
                this.zzajQ.add(dataType);
            }
            return this;
        }

        public Builder addSession(Session session) {
            com.google.android.gms.common.internal.zzu.zzb(!this.zzalS, "All sessions already marked for deletion");
            com.google.android.gms.common.internal.zzu.zzb(session != null, "Must specify a valid session");
            com.google.android.gms.common.internal.zzu.zzb(session.getEndTime(TimeUnit.MILLISECONDS) > 0, "Cannot delete an ongoing session. Please stop the session prior to deleting it");
            this.zzalQ.add(session);
            return this;
        }

        public DataDeleteRequest build() {
            boolean z = false;
            com.google.android.gms.common.internal.zzu.zza(this.zzKT > 0 && this.zzajH > this.zzKT, "Must specify a valid time interval");
            boolean z2 = (!this.zzalR && this.zzalP.isEmpty() && this.zzajQ.isEmpty()) ? false : true;
            boolean z3 = this.zzalS || !this.zzalQ.isEmpty();
            if (z2 || z3) {
                z = true;
            }
            com.google.android.gms.common.internal.zzu.zza(z, "No data or session marked for deletion");
            zzqX();
            return new DataDeleteRequest(this);
        }

        public Builder deleteAllData() {
            com.google.android.gms.common.internal.zzu.zzb(this.zzajQ.isEmpty() && this.zzalP.isEmpty(), "Specific data source/type already specified for deletion. DataSources: %s DataTypes: %s", this.zzalP, this.zzajQ);
            this.zzalR = true;
            return this;
        }

        public Builder deleteAllSessions() {
            com.google.android.gms.common.internal.zzu.zzb(this.zzalQ.isEmpty(), "Specific sessions already added for deletion: %s", this.zzalQ);
            this.zzalS = true;
            return this;
        }

        public Builder setTimeInterval(long startTime, long endTime, TimeUnit timeUnit) {
            com.google.android.gms.common.internal.zzu.zzb(startTime > 0, "Invalid start time :%d", Long.valueOf(startTime));
            com.google.android.gms.common.internal.zzu.zzb(endTime > startTime, "Invalid end time :%d", Long.valueOf(endTime));
            this.zzKT = timeUnit.toMillis(startTime);
            this.zzajH = timeUnit.toMillis(endTime);
            return this;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DataDeleteRequest(int versionCode, long startTimeMillis, long endTimeMillis, List<DataSource> dataSources, List<DataType> dataTypes, List<Session> sessions, boolean deleteAllData, boolean deleteAllSessions, IBinder callback, String packageName) {
        this.zzCY = versionCode;
        this.zzKT = startTimeMillis;
        this.zzajH = endTimeMillis;
        this.zzalP = Collections.unmodifiableList(dataSources);
        this.zzajQ = Collections.unmodifiableList(dataTypes);
        this.zzalQ = sessions;
        this.zzalR = deleteAllData;
        this.zzalS = deleteAllSessions;
        this.zzalN = callback == null ? null : zzmu.zza.zzbF(callback);
        this.zzMZ = packageName;
    }

    public DataDeleteRequest(long startTimeMillis, long endTimeMillis, List<DataSource> dataSources, List<DataType> dataTypes, List<Session> sessions, boolean deleteAllData, boolean deleteAllSessions, zzmu callback, String packageName) {
        this.zzCY = 2;
        this.zzKT = startTimeMillis;
        this.zzajH = endTimeMillis;
        this.zzalP = Collections.unmodifiableList(dataSources);
        this.zzajQ = Collections.unmodifiableList(dataTypes);
        this.zzalQ = sessions;
        this.zzalR = deleteAllData;
        this.zzalS = deleteAllSessions;
        this.zzalN = callback;
        this.zzMZ = packageName;
    }

    private DataDeleteRequest(Builder builder) {
        this(builder.zzKT, builder.zzajH, builder.zzalP, builder.zzajQ, builder.zzalQ, builder.zzalR, builder.zzalS, null, null);
    }

    public DataDeleteRequest(DataDeleteRequest request, zzmu callback, String packageName) {
        this(request.zzKT, request.zzajH, request.zzalP, request.zzajQ, request.zzalQ, request.zzalR, request.zzalS, callback, packageName);
    }

    private boolean zzb(DataDeleteRequest dataDeleteRequest) {
        return this.zzKT == dataDeleteRequest.zzKT && this.zzajH == dataDeleteRequest.zzajH && com.google.android.gms.common.internal.zzt.equal(this.zzalP, dataDeleteRequest.zzalP) && com.google.android.gms.common.internal.zzt.equal(this.zzajQ, dataDeleteRequest.zzajQ) && com.google.android.gms.common.internal.zzt.equal(this.zzalQ, dataDeleteRequest.zzalQ) && this.zzalR == dataDeleteRequest.zzalR && this.zzalS == dataDeleteRequest.zzalS;
    }

    public boolean deleteAllData() {
        return this.zzalR;
    }

    public boolean deleteAllSessions() {
        return this.zzalS;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        return o == this || ((o instanceof DataDeleteRequest) && zzb((DataDeleteRequest) o));
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

    public String getPackageName() {
        return this.zzMZ;
    }

    public List<Session> getSessions() {
        return this.zzalQ;
    }

    public long getStartTime(TimeUnit timeUnit) {
        return timeUnit.convert(this.zzKT, TimeUnit.MILLISECONDS);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(Long.valueOf(this.zzKT), Long.valueOf(this.zzajH));
    }

    public String toString() {
        return com.google.android.gms.common.internal.zzt.zzt(this).zzg("startTimeMillis", Long.valueOf(this.zzKT)).zzg("endTimeMillis", Long.valueOf(this.zzajH)).zzg("dataSources", this.zzalP).zzg("dateTypes", this.zzajQ).zzg("sessions", this.zzalQ).zzg("deleteAllData", Boolean.valueOf(this.zzalR)).zzg("deleteAllSessions", Boolean.valueOf(this.zzalS)).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzd.zza(this, dest, flags);
    }

    public long zzkt() {
        return this.zzKT;
    }

    public IBinder zzqU() {
        if (this.zzalN == null) {
            return null;
        }
        return this.zzalN.asBinder();
    }

    public boolean zzqV() {
        return this.zzalR;
    }

    public boolean zzqW() {
        return this.zzalS;
    }

    public long zzqs() {
        return this.zzajH;
    }
}
