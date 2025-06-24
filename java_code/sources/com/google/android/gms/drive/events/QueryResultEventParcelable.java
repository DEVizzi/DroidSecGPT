package com.google.android.gms.drive.events;

import android.os.Parcel;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.drive.WriteAwareParcelable;
/* loaded from: classes.dex */
public class QueryResultEventParcelable extends WriteAwareParcelable implements DriveEvent {
    public static final zzk CREATOR = new zzk();
    final int zzCY;
    final DataHolder zzWu;
    final boolean zzaei;
    final int zzaej;

    /* JADX INFO: Access modifiers changed from: package-private */
    public QueryResultEventParcelable(int versionCode, DataHolder dataHolder, boolean isStatusChanged, int queryStatus) {
        this.zzCY = versionCode;
        this.zzWu = dataHolder;
        this.zzaei = isStatusChanged;
        this.zzaej = queryStatus;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // com.google.android.gms.drive.events.DriveEvent
    public int getType() {
        return 3;
    }

    @Override // com.google.android.gms.drive.WriteAwareParcelable
    public void zzI(Parcel parcel, int i) {
        zzk.zza(this, parcel, i);
    }

    public DataHolder zzpx() {
        return this.zzWu;
    }

    public boolean zzpy() {
        return this.zzaei;
    }

    public int zzpz() {
        return this.zzaej;
    }
}
