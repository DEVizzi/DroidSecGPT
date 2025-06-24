package com.google.android.gms.fitness.request;

import android.os.SystemClock;
import com.google.android.gms.fitness.data.DataSource;
import com.google.android.gms.fitness.data.DataType;
import com.google.android.gms.location.LocationRequest;
import java.util.concurrent.TimeUnit;
/* loaded from: classes.dex */
public class SensorRequest {
    public static final int ACCURACY_MODE_DEFAULT = 2;
    public static final int ACCURACY_MODE_HIGH = 3;
    public static final int ACCURACY_MODE_LOW = 1;
    private final DataType zzajF;
    private final DataSource zzajG;
    private final long zzakP;
    private final int zzakQ;
    private final long zzamA;
    private final long zzamu;
    private final long zzamv;
    private final LocationRequest zzamz;

    /* loaded from: classes.dex */
    public static class Builder {
        private DataType zzajF;
        private DataSource zzajG;
        private long zzakP = -1;
        private long zzamv = 0;
        private long zzamu = 0;
        private boolean zzamB = false;
        private int zzakQ = 2;
        private long zzamA = Long.MAX_VALUE;

        public SensorRequest build() {
            boolean z = false;
            com.google.android.gms.common.internal.zzu.zza((this.zzajG == null && this.zzajF == null) ? false : true, "Must call setDataSource() or setDataType()");
            if (this.zzajF == null || this.zzajG == null || this.zzajF.equals(this.zzajG.getDataType())) {
                z = true;
            }
            com.google.android.gms.common.internal.zzu.zza(z, "Specified data type is incompatible with specified data source");
            return new SensorRequest(this);
        }

        public Builder setAccuracyMode(int accuracyMode) {
            this.zzakQ = SensorRequest.zzeM(accuracyMode);
            return this;
        }

        public Builder setDataSource(DataSource dataSource) {
            this.zzajG = dataSource;
            return this;
        }

        public Builder setDataType(DataType dataType) {
            this.zzajF = dataType;
            return this;
        }

        public Builder setFastestRate(int fastestInterval, TimeUnit unit) {
            com.google.android.gms.common.internal.zzu.zzb(fastestInterval >= 0, "Cannot use a negative interval");
            this.zzamB = true;
            this.zzamv = unit.toMicros(fastestInterval);
            return this;
        }

        public Builder setMaxDeliveryLatency(int interval, TimeUnit unit) {
            com.google.android.gms.common.internal.zzu.zzb(interval >= 0, "Cannot use a negative delivery interval");
            this.zzamu = unit.toMicros(interval);
            return this;
        }

        public Builder setSamplingRate(long interval, TimeUnit unit) {
            com.google.android.gms.common.internal.zzu.zzb(interval >= 0, "Cannot use a negative sampling interval");
            this.zzakP = unit.toMicros(interval);
            if (!this.zzamB) {
                this.zzamv = this.zzakP / 2;
            }
            return this;
        }

        public Builder setTimeout(long timeout, TimeUnit timeUnit) {
            com.google.android.gms.common.internal.zzu.zzb(timeout > 0, "Invalid time out value specified: %d", Long.valueOf(timeout));
            com.google.android.gms.common.internal.zzu.zzb(timeUnit != null, "Invalid time unit specified");
            this.zzamA = timeUnit.toMicros(timeout);
            return this;
        }
    }

    private SensorRequest(DataSource dataSource, LocationRequest locationRequest) {
        this.zzamz = locationRequest;
        this.zzakP = TimeUnit.MILLISECONDS.toMicros(locationRequest.getInterval());
        this.zzamv = TimeUnit.MILLISECONDS.toMicros(locationRequest.getFastestInterval());
        this.zzamu = this.zzakP;
        this.zzajF = dataSource.getDataType();
        this.zzakQ = zza(locationRequest);
        this.zzajG = dataSource;
        long expirationTime = locationRequest.getExpirationTime();
        if (expirationTime == Long.MAX_VALUE) {
            this.zzamA = Long.MAX_VALUE;
        } else {
            this.zzamA = TimeUnit.MILLISECONDS.toMicros(expirationTime - SystemClock.elapsedRealtime());
        }
    }

    private SensorRequest(Builder builder) {
        this.zzajG = builder.zzajG;
        this.zzajF = builder.zzajF;
        this.zzakP = builder.zzakP;
        this.zzamv = builder.zzamv;
        this.zzamu = builder.zzamu;
        this.zzakQ = builder.zzakQ;
        this.zzamz = null;
        this.zzamA = builder.zzamA;
    }

    public static SensorRequest fromLocationRequest(DataSource dataSource, LocationRequest locationRequest) {
        return new SensorRequest(dataSource, locationRequest);
    }

    private static int zza(LocationRequest locationRequest) {
        switch (locationRequest.getPriority()) {
            case 100:
                return 3;
            case 104:
                return 1;
            default:
                return 2;
        }
    }

    private boolean zza(SensorRequest sensorRequest) {
        return com.google.android.gms.common.internal.zzt.equal(this.zzajG, sensorRequest.zzajG) && com.google.android.gms.common.internal.zzt.equal(this.zzajF, sensorRequest.zzajF) && this.zzakP == sensorRequest.zzakP && this.zzamv == sensorRequest.zzamv && this.zzamu == sensorRequest.zzamu && this.zzakQ == sensorRequest.zzakQ && com.google.android.gms.common.internal.zzt.equal(this.zzamz, sensorRequest.zzamz) && this.zzamA == sensorRequest.zzamA;
    }

    public static int zzeM(int i) {
        switch (i) {
            case 1:
            case 3:
                return i;
            case 2:
            default:
                return 2;
        }
    }

    public boolean equals(Object that) {
        return this == that || ((that instanceof SensorRequest) && zza((SensorRequest) that));
    }

    public int getAccuracyMode() {
        return this.zzakQ;
    }

    public DataSource getDataSource() {
        return this.zzajG;
    }

    public DataType getDataType() {
        return this.zzajF;
    }

    public long getFastestRate(TimeUnit timeUnit) {
        return timeUnit.convert(this.zzamv, TimeUnit.MICROSECONDS);
    }

    public long getMaxDeliveryLatency(TimeUnit timeUnit) {
        return timeUnit.convert(this.zzamu, TimeUnit.MICROSECONDS);
    }

    public long getSamplingRate(TimeUnit timeUnit) {
        return timeUnit.convert(this.zzakP, TimeUnit.MICROSECONDS);
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(this.zzajG, this.zzajF, Long.valueOf(this.zzakP), Long.valueOf(this.zzamv), Long.valueOf(this.zzamu), Integer.valueOf(this.zzakQ), this.zzamz, Long.valueOf(this.zzamA));
    }

    public String toString() {
        return com.google.android.gms.common.internal.zzt.zzt(this).zzg("dataSource", this.zzajG).zzg("dataType", this.zzajF).zzg("samplingRateMicros", Long.valueOf(this.zzakP)).zzg("deliveryLatencyMicros", Long.valueOf(this.zzamu)).zzg("timeOutMicros", Long.valueOf(this.zzamA)).toString();
    }

    public long zzrm() {
        return this.zzamA;
    }
}
