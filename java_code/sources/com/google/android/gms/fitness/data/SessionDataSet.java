package com.google.android.gms.fitness.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class SessionDataSet implements SafeParcelable {
    public static final Parcelable.Creator<SessionDataSet> CREATOR = new zzq();
    final int zzCY;
    private final Session zzajJ;
    private final DataSet zzakO;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SessionDataSet(int versionCode, Session session, DataSet dataSet) {
        this.zzCY = versionCode;
        this.zzajJ = session;
        this.zzakO = dataSet;
    }

    private boolean zza(SessionDataSet sessionDataSet) {
        return com.google.android.gms.common.internal.zzt.equal(this.zzajJ, sessionDataSet.zzajJ) && com.google.android.gms.common.internal.zzt.equal(this.zzakO, sessionDataSet.zzakO);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        return o == this || ((o instanceof SessionDataSet) && zza((SessionDataSet) o));
    }

    public Session getSession() {
        return this.zzajJ;
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(this.zzajJ, this.zzakO);
    }

    public String toString() {
        return com.google.android.gms.common.internal.zzt.zzt(this).zzg("session", this.zzajJ).zzg("dataSet", this.zzakO).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzq.zza(this, dest, flags);
    }

    public DataSet zzqK() {
        return this.zzakO;
    }
}
