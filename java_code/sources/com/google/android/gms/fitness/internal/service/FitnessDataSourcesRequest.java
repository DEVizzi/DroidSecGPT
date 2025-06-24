package com.google.android.gms.fitness.internal.service;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.fitness.data.DataType;
import java.util.Collections;
import java.util.List;
/* loaded from: classes.dex */
public class FitnessDataSourcesRequest implements SafeParcelable {
    public static final Parcelable.Creator<FitnessDataSourcesRequest> CREATOR = new zza();
    private final int zzCY;
    private final List<DataType> zzajQ;

    /* JADX INFO: Access modifiers changed from: package-private */
    public FitnessDataSourcesRequest(int versionCode, List<DataType> dataTypes) {
        this.zzCY = versionCode;
        this.zzajQ = dataTypes;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public List<DataType> getDataTypes() {
        return Collections.unmodifiableList(this.zzajQ);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public String toString() {
        return zzt.zzt(this).zzg("dataTypes", this.zzajQ).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zza.zza(this, parcel, flags);
    }
}
