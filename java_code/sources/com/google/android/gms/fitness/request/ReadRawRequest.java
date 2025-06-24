package com.google.android.gms.fitness.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.internal.zzmq;
import java.util.List;
/* loaded from: classes.dex */
public class ReadRawRequest implements SafeParcelable {
    public static final Parcelable.Creator<ReadRawRequest> CREATOR = new zzq();
    private final int zzCY;
    private final String zzMZ;
    private final boolean zzalZ;
    private final boolean zzama;
    private final zzmq zzamo;
    private final List<DataSourceQueryParams> zzamp;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ReadRawRequest(int versionCode, IBinder callback, String packageName, List<DataSourceQueryParams> queryParams, boolean flushBufferBeforeRead, boolean serverQueriesEnabled) {
        this.zzCY = versionCode;
        this.zzamo = zzmq.zza.zzbB(callback);
        this.zzamp = queryParams;
        this.zzMZ = packageName;
        this.zzalZ = flushBufferBeforeRead;
        this.zzama = serverQueriesEnabled;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String getPackageName() {
        return this.zzMZ;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzq.zza(this, parcel, flags);
    }

    public IBinder zzqU() {
        if (this.zzamo != null) {
            return this.zzamo.asBinder();
        }
        return null;
    }

    public boolean zzqZ() {
        return this.zzama;
    }

    public boolean zzra() {
        return this.zzalZ;
    }

    public List<DataSourceQueryParams> zzrf() {
        return this.zzamp;
    }
}
