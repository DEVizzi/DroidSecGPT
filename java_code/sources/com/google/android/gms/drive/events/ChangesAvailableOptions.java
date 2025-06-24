package com.google.android.gms.drive.events;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.drive.DriveSpace;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
/* loaded from: classes.dex */
public final class ChangesAvailableOptions implements SafeParcelable {
    public static final Parcelable.Creator<ChangesAvailableOptions> CREATOR = new zzd();
    final int zzCY;
    final int zzadP;
    final boolean zzadQ;
    final List<DriveSpace> zzadR;
    private final Set<DriveSpace> zzadS;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ChangesAvailableOptions(int versionCode, int changesSizeLimit, boolean repeats, List<DriveSpace> spacesList) {
        this(versionCode, changesSizeLimit, repeats, spacesList, spacesList == null ? null : new HashSet(spacesList));
    }

    private ChangesAvailableOptions(int versionCode, int changesSizeLimit, boolean repeats, List<DriveSpace> spacesList, Set<DriveSpace> spaces) {
        this.zzCY = versionCode;
        this.zzadP = changesSizeLimit;
        this.zzadQ = repeats;
        this.zzadR = spacesList;
        this.zzadS = spaces;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        if (o == null || o.getClass() != getClass()) {
            return false;
        }
        if (o != this) {
            ChangesAvailableOptions changesAvailableOptions = (ChangesAvailableOptions) o;
            return zzt.equal(this.zzadS, changesAvailableOptions.zzadS) && this.zzadP == changesAvailableOptions.zzadP && this.zzadQ == changesAvailableOptions.zzadQ;
        }
        return true;
    }

    public int hashCode() {
        return zzt.hashCode(this.zzadS, Integer.valueOf(this.zzadP), Boolean.valueOf(this.zzadQ));
    }

    public String toString() {
        return String.format(Locale.US, "ChangesAvailableOptions[ChangesSizeLimit=%d, Repeats=%s, Spaces=%s]", Integer.valueOf(this.zzadP), Boolean.valueOf(this.zzadQ), this.zzadR);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzd.zza(this, dest, flags);
    }
}
