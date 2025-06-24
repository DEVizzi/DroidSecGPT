package com.google.android.gms.drive;

import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
/* loaded from: classes.dex */
public class DriveSpace implements SafeParcelable {
    public static final Parcelable.Creator<DriveSpace> CREATOR = new zzg();
    public static final DriveSpace zzadi = new DriveSpace("DRIVE");
    public static final DriveSpace zzadj = new DriveSpace("APP_DATA_FOLDER");
    public static final DriveSpace zzadk = new DriveSpace("PHOTOS");
    public static final Set<DriveSpace> zzadl = Collections.unmodifiableSet(new HashSet(Arrays.asList(zzadi, zzadj, zzadk)));
    public static final String zzadm = TextUtils.join(",", zzadl.toArray());
    private final String mName;
    final int zzCY;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DriveSpace(int versionCode, String name) {
        this.zzCY = versionCode;
        this.mName = (String) zzu.zzu(name);
    }

    private DriveSpace(String name) {
        this(1, name);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        if (o == null || o.getClass() != DriveSpace.class) {
            return false;
        }
        return this.mName.equals(((DriveSpace) o).mName);
    }

    public String getName() {
        return this.mName;
    }

    public int hashCode() {
        return 1247068382 ^ this.mName.hashCode();
    }

    public String toString() {
        return this.mName;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzg.zza(this, out, flags);
    }
}
