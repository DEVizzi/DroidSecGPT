package com.google.android.gms.fitness.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import java.util.List;
/* loaded from: classes.dex */
public final class RawDataSet implements SafeParcelable {
    public static final Parcelable.Creator<RawDataSet> CREATOR = new zzo();
    final int zzCY;
    public final boolean zzajU;
    public final int zzakH;
    public final int zzakJ;
    public final List<RawDataPoint> zzakK;

    public RawDataSet(int versionCode, int dataSourceIndex, int dataTypeIndex, List<RawDataPoint> rawDataPoints, boolean serverHasMoreData) {
        this.zzCY = versionCode;
        this.zzakH = dataSourceIndex;
        this.zzakJ = dataTypeIndex;
        this.zzakK = rawDataPoints;
        this.zzajU = serverHasMoreData;
    }

    public RawDataSet(DataSet dataSet, List<DataSource> uniqueDataSources, List<DataType> uniqueDataTypes) {
        this.zzCY = 3;
        this.zzakK = dataSet.zzk(uniqueDataSources);
        this.zzajU = dataSet.zzqr();
        this.zzakH = zzs.zza(dataSet.getDataSource(), uniqueDataSources);
        this.zzakJ = zzs.zza(dataSet.getDataType(), uniqueDataTypes);
    }

    private boolean zza(RawDataSet rawDataSet) {
        return this.zzakH == rawDataSet.zzakH && this.zzajU == rawDataSet.zzajU && com.google.android.gms.common.internal.zzt.equal(this.zzakK, rawDataSet.zzakK);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        return this == o || ((o instanceof RawDataSet) && zza((RawDataSet) o));
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(Integer.valueOf(this.zzakH));
    }

    public String toString() {
        return String.format("RawDataSet{%s@[%s]}", Integer.valueOf(this.zzakH), this.zzakK);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzo.zza(this, parcel, flags);
    }
}
