package com.google.android.gms.fitness.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.fitness.data.DataType;
import com.google.android.gms.internal.zzkx;
import com.google.android.gms.internal.zzmg;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
/* loaded from: classes.dex */
public class DataSourcesRequest implements SafeParcelable {
    public static final Parcelable.Creator<DataSourcesRequest> CREATOR = new zzh();
    private final int zzCY;
    private final String zzMZ;
    private final List<DataType> zzajQ;
    private final List<Integer> zzamf;
    private final boolean zzamg;
    private final zzmg zzamh;

    /* loaded from: classes.dex */
    public static class Builder {
        private DataType[] zzami = new DataType[0];
        private int[] zzamj = {0, 1};
        private boolean zzamg = false;

        public DataSourcesRequest build() {
            com.google.android.gms.common.internal.zzu.zza(this.zzami.length > 0, "Must add at least one data type");
            com.google.android.gms.common.internal.zzu.zza(this.zzamj.length > 0, "Must add at least one data source type");
            return new DataSourcesRequest(this);
        }

        public Builder setDataSourceTypes(int... dataSourceTypes) {
            this.zzamj = dataSourceTypes;
            return this;
        }

        public Builder setDataTypes(DataType... dataTypes) {
            this.zzami = dataTypes;
            return this;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DataSourcesRequest(int versionCode, List<DataType> dataTypes, List<Integer> dataSourceTypes, boolean includeDbOnlySources, IBinder callback, String packageName) {
        this.zzCY = versionCode;
        this.zzajQ = dataTypes;
        this.zzamf = dataSourceTypes;
        this.zzamg = includeDbOnlySources;
        this.zzamh = callback == null ? null : zzmg.zza.zzbr(callback);
        this.zzMZ = packageName;
    }

    private DataSourcesRequest(Builder builder) {
        this(zzkx.zzb(builder.zzami), Arrays.asList(zzkx.zza(builder.zzamj)), builder.zzamg, null, null);
    }

    public DataSourcesRequest(DataSourcesRequest request, zzmg callback, String packageName) {
        this(request.zzajQ, request.zzamf, request.zzamg, callback, packageName);
    }

    public DataSourcesRequest(List<DataType> dataTypes, List<Integer> dataSourceTypes, boolean includeDbOnlySources, zzmg callback, String packageName) {
        this.zzCY = 3;
        this.zzajQ = dataTypes;
        this.zzamf = dataSourceTypes;
        this.zzamg = includeDbOnlySources;
        this.zzamh = callback;
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

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public String toString() {
        zzt.zza zzg = com.google.android.gms.common.internal.zzt.zzt(this).zzg("dataTypes", this.zzajQ).zzg("sourceTypes", this.zzamf);
        if (this.zzamg) {
            zzg.zzg("includeDbOnlySources", "true");
        }
        return zzg.toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzh.zza(this, parcel, flags);
    }

    public IBinder zzqU() {
        if (this.zzamh == null) {
            return null;
        }
        return this.zzamh.asBinder();
    }

    public List<Integer> zzrd() {
        return this.zzamf;
    }

    public boolean zzre() {
        return this.zzamg;
    }
}
