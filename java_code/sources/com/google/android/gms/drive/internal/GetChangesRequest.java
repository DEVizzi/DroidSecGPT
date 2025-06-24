package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.drive.ChangeSequenceNumber;
import com.google.android.gms.drive.DriveSpace;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
/* loaded from: classes.dex */
public class GetChangesRequest implements SafeParcelable {
    public static final Parcelable.Creator<GetChangesRequest> CREATOR = new zzaf();
    final int zzCY;
    final List<DriveSpace> zzadR;
    private final Set<DriveSpace> zzadS;
    final ChangeSequenceNumber zzafJ;
    final int zzafK;

    /* JADX INFO: Access modifiers changed from: package-private */
    public GetChangesRequest(int versionCode, ChangeSequenceNumber fromSequenceNumber, int maxResults, List<DriveSpace> spacesList) {
        this(versionCode, fromSequenceNumber, maxResults, spacesList, spacesList == null ? null : new HashSet(spacesList));
    }

    private GetChangesRequest(int versionCode, ChangeSequenceNumber fromSequenceNumber, int maxResults, List<DriveSpace> spacesList, Set<DriveSpace> spaces) {
        this.zzCY = versionCode;
        this.zzafJ = fromSequenceNumber;
        this.zzafK = maxResults;
        this.zzadR = spacesList;
        this.zzadS = spaces;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzaf.zza(this, dest, flags);
    }
}
