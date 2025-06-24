package com.google.android.gms.fitness.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.fitness.data.DataSource;
import com.google.android.gms.fitness.data.DataType;
import com.google.android.gms.internal.zzms;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
/* loaded from: classes.dex */
public class SessionReadRequest implements SafeParcelable {
    public static final Parcelable.Creator<SessionReadRequest> CREATOR = new zzv();
    private final int zzCY;
    private final String zzFE;
    private final long zzKT;
    private final String zzMZ;
    private final long zzajH;
    private final List<DataType> zzajQ;
    private final List<DataSource> zzalP;
    private final String zzamE;
    private boolean zzamF;
    private final List<String> zzamG;
    private final zzms zzamH;
    private final boolean zzama;

    /* loaded from: classes.dex */
    public static class Builder {
        private String zzFE;
        private String zzamE;
        private long zzKT = 0;
        private long zzajH = 0;
        private List<DataType> zzajQ = new ArrayList();
        private List<DataSource> zzalP = new ArrayList();
        private boolean zzamF = false;
        private boolean zzama = false;
        private List<String> zzamG = new ArrayList();

        public SessionReadRequest build() {
            com.google.android.gms.common.internal.zzu.zzb(this.zzKT > 0, "Invalid start time: %s", Long.valueOf(this.zzKT));
            com.google.android.gms.common.internal.zzu.zzb(this.zzajH > 0 && this.zzajH > this.zzKT, "Invalid end time: %s", Long.valueOf(this.zzajH));
            return new SessionReadRequest(this);
        }

        public Builder enableServerQueries() {
            this.zzama = true;
            return this;
        }

        public Builder excludePackage(String appPackageName) {
            com.google.android.gms.common.internal.zzu.zzb(appPackageName, "Attempting to use a null package name");
            if (!this.zzamG.contains(appPackageName)) {
                this.zzamG.add(appPackageName);
            }
            return this;
        }

        public Builder read(DataSource dataSource) {
            com.google.android.gms.common.internal.zzu.zzb(dataSource, "Attempting to add a null data source");
            if (!this.zzalP.contains(dataSource)) {
                this.zzalP.add(dataSource);
            }
            return this;
        }

        public Builder read(DataType dataType) {
            com.google.android.gms.common.internal.zzu.zzb(dataType, "Attempting to use a null data type");
            if (!this.zzajQ.contains(dataType)) {
                this.zzajQ.add(dataType);
            }
            return this;
        }

        public Builder readSessionsFromAllApps() {
            this.zzamF = true;
            return this;
        }

        public Builder setSessionId(String sessionId) {
            this.zzFE = sessionId;
            return this;
        }

        public Builder setSessionName(String sessionName) {
            this.zzamE = sessionName;
            return this;
        }

        public Builder setTimeInterval(long startTime, long endTime, TimeUnit timeUnit) {
            this.zzKT = timeUnit.toMillis(startTime);
            this.zzajH = timeUnit.toMillis(endTime);
            return this;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SessionReadRequest(int versionCode, String sessionName, String sessionId, long startTimeMillis, long endTimeMillis, List<DataType> dataTypes, List<DataSource> dataSources, boolean getSessionsFromAllApps, boolean serverQueriesEnabled, List<String> excludedPackages, IBinder callback, String packageName) {
        this.zzCY = versionCode;
        this.zzamE = sessionName;
        this.zzFE = sessionId;
        this.zzKT = startTimeMillis;
        this.zzajH = endTimeMillis;
        this.zzajQ = Collections.unmodifiableList(dataTypes);
        this.zzalP = Collections.unmodifiableList(dataSources);
        this.zzamF = getSessionsFromAllApps;
        this.zzama = serverQueriesEnabled;
        this.zzamG = excludedPackages;
        this.zzamH = callback == null ? null : zzms.zza.zzbD(callback);
        this.zzMZ = packageName;
    }

    private SessionReadRequest(Builder builder) {
        this(builder.zzamE, builder.zzFE, builder.zzKT, builder.zzajH, builder.zzajQ, builder.zzalP, builder.zzamF, builder.zzama, builder.zzamG, null, null);
    }

    public SessionReadRequest(SessionReadRequest request, zzms callback, String packageName) {
        this(request.zzamE, request.zzFE, request.zzKT, request.zzajH, request.zzajQ, request.zzalP, request.zzamF, request.zzama, request.zzamG, callback, packageName);
    }

    public SessionReadRequest(String sessionName, String sessionId, long startTimeMillis, long endTimeMillis, List<DataType> dataTypes, List<DataSource> dataSources, boolean getSessionsFromAllApps, boolean serverQueriesEnabled, List<String> excludedPackages, zzms callback, String packageName) {
        this.zzCY = 4;
        this.zzamE = sessionName;
        this.zzFE = sessionId;
        this.zzKT = startTimeMillis;
        this.zzajH = endTimeMillis;
        this.zzajQ = Collections.unmodifiableList(dataTypes);
        this.zzalP = Collections.unmodifiableList(dataSources);
        this.zzamF = getSessionsFromAllApps;
        this.zzama = serverQueriesEnabled;
        this.zzamG = excludedPackages;
        this.zzamH = callback;
        this.zzMZ = packageName;
    }

    private boolean zzb(SessionReadRequest sessionReadRequest) {
        return com.google.android.gms.common.internal.zzt.equal(this.zzamE, sessionReadRequest.zzamE) && this.zzFE.equals(sessionReadRequest.zzFE) && this.zzKT == sessionReadRequest.zzKT && this.zzajH == sessionReadRequest.zzajH && com.google.android.gms.common.internal.zzt.equal(this.zzajQ, sessionReadRequest.zzajQ) && com.google.android.gms.common.internal.zzt.equal(this.zzalP, sessionReadRequest.zzalP) && this.zzamF == sessionReadRequest.zzamF && this.zzamG.equals(sessionReadRequest.zzamG) && this.zzama == sessionReadRequest.zzama;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        return this == o || ((o instanceof SessionReadRequest) && zzb((SessionReadRequest) o));
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

    public List<String> getExcludedPackages() {
        return this.zzamG;
    }

    public String getPackageName() {
        return this.zzMZ;
    }

    public String getSessionId() {
        return this.zzFE;
    }

    public String getSessionName() {
        return this.zzamE;
    }

    public long getStartTime(TimeUnit timeUnit) {
        return timeUnit.convert(this.zzKT, TimeUnit.MILLISECONDS);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(this.zzamE, this.zzFE, Long.valueOf(this.zzKT), Long.valueOf(this.zzajH));
    }

    public boolean includeSessionsFromAllApps() {
        return this.zzamF;
    }

    public String toString() {
        return com.google.android.gms.common.internal.zzt.zzt(this).zzg("sessionName", this.zzamE).zzg("sessionId", this.zzFE).zzg("startTimeMillis", Long.valueOf(this.zzKT)).zzg("endTimeMillis", Long.valueOf(this.zzajH)).zzg("dataTypes", this.zzajQ).zzg("dataSources", this.zzalP).zzg("sessionsFromAllApps", Boolean.valueOf(this.zzamF)).zzg("excludedPackages", this.zzamG).zzg("useServer", Boolean.valueOf(this.zzama)).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzv.zza(this, dest, flags);
    }

    public long zzkt() {
        return this.zzKT;
    }

    public IBinder zzqU() {
        if (this.zzamH == null) {
            return null;
        }
        return this.zzamH.asBinder();
    }

    public boolean zzqZ() {
        return this.zzama;
    }

    public long zzqs() {
        return this.zzajH;
    }

    public boolean zzro() {
        return this.zzamF;
    }
}
