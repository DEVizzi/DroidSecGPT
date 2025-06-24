package com.google.android.gms.fitness.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.fitness.data.DataType;
import com.google.android.gms.fitness.request.zza;
import com.google.android.gms.fitness.request.zzn;
import com.google.android.gms.internal.zzkx;
import com.google.android.gms.internal.zzmu;
import java.util.Collections;
import java.util.List;
/* loaded from: classes.dex */
public class StartBleScanRequest implements SafeParcelable {
    public static final Parcelable.Creator<StartBleScanRequest> CREATOR = new zzaa();
    private final int zzCY;
    private final String zzMZ;
    private final List<DataType> zzajQ;
    private final zzmu zzalN;
    private final zzn zzamK;
    private final int zzamL;

    /* loaded from: classes.dex */
    public static class Builder {
        private zzn zzamK;
        private DataType[] zzami = new DataType[0];
        private int zzamL = 10;

        public StartBleScanRequest build() {
            com.google.android.gms.common.internal.zzu.zza(this.zzamK != null, "Must set BleScanCallback");
            return new StartBleScanRequest(this);
        }

        public Builder setBleScanCallback(BleScanCallback bleScanCallback) {
            zza(zza.C0064zza.zzqS().zza(bleScanCallback));
            return this;
        }

        public Builder setDataTypes(DataType... dataTypes) {
            this.zzami = dataTypes;
            return this;
        }

        public Builder setTimeoutSecs(int stopTimeSecs) {
            com.google.android.gms.common.internal.zzu.zzb(stopTimeSecs > 0, "Stop time must be greater than zero");
            com.google.android.gms.common.internal.zzu.zzb(stopTimeSecs <= 60, "Stop time must be less than 1 minute");
            this.zzamL = stopTimeSecs;
            return this;
        }

        public Builder zza(zzn zznVar) {
            this.zzamK = zznVar;
            return this;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public StartBleScanRequest(int versionCode, List<DataType> dataTypes, IBinder bleScanCallback, int timeoutSecs, IBinder callback, String packageName) {
        this.zzCY = versionCode;
        this.zzajQ = dataTypes;
        this.zzamK = zzn.zza.zzbI(bleScanCallback);
        this.zzamL = timeoutSecs;
        this.zzalN = callback == null ? null : zzmu.zza.zzbF(callback);
        this.zzMZ = packageName;
    }

    private StartBleScanRequest(Builder builder) {
        this(zzkx.zzb(builder.zzami), builder.zzamK, builder.zzamL, null, null);
    }

    public StartBleScanRequest(StartBleScanRequest request, zzmu callback, String packageName) {
        this(request.zzajQ, request.zzamK, request.zzamL, callback, packageName);
    }

    public StartBleScanRequest(List<DataType> dataTypes, zzn bleScanCallback, int timeoutSecs, zzmu callback, String packageName) {
        this.zzCY = 3;
        this.zzajQ = dataTypes;
        this.zzamK = bleScanCallback;
        this.zzamL = timeoutSecs;
        this.zzalN = callback;
        this.zzMZ = packageName;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public List<DataType> getDataTypes() {
        return Collections.unmodifiableList(this.zzajQ);
    }

    public String getPackageName() {
        return this.zzMZ;
    }

    public int getTimeoutSecs() {
        return this.zzamL;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public String toString() {
        return com.google.android.gms.common.internal.zzt.zzt(this).zzg("dataTypes", this.zzajQ).zzg("timeoutSecs", Integer.valueOf(this.zzamL)).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzaa.zza(this, parcel, flags);
    }

    public IBinder zzqU() {
        if (this.zzalN == null) {
            return null;
        }
        return this.zzalN.asBinder();
    }

    public IBinder zzrq() {
        return this.zzamK.asBinder();
    }
}
