package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import java.util.List;
/* loaded from: classes.dex */
public class CheckResourceIdsExistRequest implements SafeParcelable {
    public static final Parcelable.Creator<CheckResourceIdsExistRequest> CREATOR = new zzf();
    private final int zzCY;
    private final List<String> zzaep;

    /* JADX INFO: Access modifiers changed from: package-private */
    public CheckResourceIdsExistRequest(int versionCode, List<String> resourceIds) {
        this.zzCY = versionCode;
        this.zzaep = resourceIds;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzf.zza(this, dest, flags);
    }

    public List<String> zzpA() {
        return this.zzaep;
    }
}
