package com.google.android.gms.fitness.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
/* loaded from: classes.dex */
public final class DataSet implements SafeParcelable {
    public static final Parcelable.Creator<DataSet> CREATOR = new zze();
    private final int zzCY;
    private final DataType zzajF;
    private final DataSource zzajG;
    private boolean zzajU;
    private final List<DataPoint> zzakb;
    private final List<DataSource> zzakc;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DataSet(int versionCode, DataSource dataSource, DataType dataType, List<RawDataPoint> dataPoints, List<DataSource> uniqueDataSources, boolean serverHasMoreData) {
        this.zzajU = false;
        this.zzCY = versionCode;
        this.zzajG = dataSource;
        this.zzajF = dataSource.getDataType();
        this.zzajU = serverHasMoreData;
        this.zzakb = new ArrayList(dataPoints.size());
        this.zzakc = versionCode < 2 ? Collections.singletonList(dataSource) : uniqueDataSources;
        for (RawDataPoint rawDataPoint : dataPoints) {
            this.zzakb.add(new DataPoint(this.zzakc, rawDataPoint));
        }
    }

    public DataSet(DataSource dataSource) {
        this.zzajU = false;
        this.zzCY = 3;
        this.zzajG = (DataSource) zzu.zzu(dataSource);
        this.zzajF = dataSource.getDataType();
        this.zzakb = new ArrayList();
        this.zzakc = new ArrayList();
        this.zzakc.add(this.zzajG);
    }

    public DataSet(RawDataSet dataSet, List<DataSource> uniqueDataSources) {
        this.zzajU = false;
        this.zzCY = 3;
        this.zzajG = (DataSource) zzb(uniqueDataSources, dataSet.zzakH);
        this.zzajF = this.zzajG.getDataType();
        this.zzakc = uniqueDataSources;
        this.zzajU = dataSet.zzajU;
        List<RawDataPoint> list = dataSet.zzakK;
        this.zzakb = new ArrayList(list.size());
        for (RawDataPoint rawDataPoint : list) {
            this.zzakb.add(new DataPoint(this.zzakc, rawDataPoint));
        }
    }

    public static DataSet create(DataSource dataSource) {
        zzu.zzb(dataSource, "DataSource should be specified");
        return new DataSet(dataSource);
    }

    private boolean zza(DataSet dataSet) {
        return com.google.android.gms.common.internal.zzt.equal(getDataType(), dataSet.getDataType()) && com.google.android.gms.common.internal.zzt.equal(this.zzajG, dataSet.zzajG) && com.google.android.gms.common.internal.zzt.equal(this.zzakb, dataSet.zzakb) && this.zzajU == dataSet.zzajU;
    }

    private static <T> T zzb(List<T> list, int i) {
        if (i < 0 || i >= list.size()) {
            return null;
        }
        return list.get(i);
    }

    public void add(DataPoint dataPoint) {
        DataSource dataSource = dataPoint.getDataSource();
        zzu.zzb(dataSource.getStreamIdentifier().equals(this.zzajG.getStreamIdentifier()), "Conflicting data sources found %s vs %s", dataSource, this.zzajG);
        dataPoint.zzqx();
        zzb(dataPoint);
    }

    public void addAll(Iterable<DataPoint> dataPoints) {
        for (DataPoint dataPoint : dataPoints) {
            add(dataPoint);
        }
    }

    public DataPoint createDataPoint() {
        return DataPoint.create(this.zzajG);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        return o == this || ((o instanceof DataSet) && zza((DataSet) o));
    }

    public List<DataPoint> getDataPoints() {
        return Collections.unmodifiableList(this.zzakb);
    }

    public DataSource getDataSource() {
        return this.zzajG;
    }

    public DataType getDataType() {
        return this.zzajG.getDataType();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(this.zzajG);
    }

    public boolean isEmpty() {
        return this.zzakb.isEmpty();
    }

    public String toString() {
        List<RawDataPoint> zzqz = zzqz();
        Object[] objArr = new Object[2];
        objArr[0] = this.zzajG.toDebugString();
        Object obj = zzqz;
        if (this.zzakb.size() >= 10) {
            obj = String.format("%d data points, first 5: %s", Integer.valueOf(this.zzakb.size()), zzqz.subList(0, 5));
        }
        objArr[1] = obj;
        return String.format("DataSet{%s %s}", objArr);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zze.zza(this, parcel, flags);
    }

    public void zzb(DataPoint dataPoint) {
        this.zzakb.add(dataPoint);
        DataSource originalDataSource = dataPoint.getOriginalDataSource();
        if (originalDataSource == null || this.zzakc.contains(originalDataSource)) {
            return;
        }
        this.zzakc.add(originalDataSource);
    }

    public void zzb(Iterable<DataPoint> iterable) {
        for (DataPoint dataPoint : iterable) {
            zzb(dataPoint);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public List<RawDataPoint> zzk(List<DataSource> list) {
        ArrayList arrayList = new ArrayList(this.zzakb.size());
        for (DataPoint dataPoint : this.zzakb) {
            arrayList.add(new RawDataPoint(dataPoint, list));
        }
        return arrayList;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public List<DataSource> zzqA() {
        return this.zzakc;
    }

    public boolean zzqr() {
        return this.zzajU;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public List<RawDataPoint> zzqz() {
        return zzk(this.zzakc);
    }
}
