package com.google.android.gms.fitness.request;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.fitness.data.DataSource;
/* loaded from: classes.dex */
public class DataSourceQueryParams implements SafeParcelable {
    public static final Parcelable.Creator<DataSourceQueryParams> CREATOR = new zzg();
    final int zzCY;
    public final long zzOw;
    public final DataSource zzajG;
    public final long zzajW;
    public final int zzalY;
    public final long zzamd;
    public final int zzame;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DataSourceQueryParams(int versionCode, DataSource dataSource, long id, long startTimeNanos, long endTimeNanos, int limit, int readBehind) {
        this.zzCY = versionCode;
        this.zzajG = dataSource;
        this.zzOw = id;
        this.zzajW = startTimeNanos;
        this.zzamd = endTimeNanos;
        this.zzalY = limit;
        this.zzame = readBehind;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzg.zza(this, dest, flags);
    }
}
