package com.google.android.gms.location.places;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
/* loaded from: classes.dex */
public final class UserDataType implements SafeParcelable {
    final int zzCY;
    final String zzEl;
    final int zzaAd;
    public static final UserDataType zzazZ = zzy("test_type", 1);
    public static final UserDataType zzaAa = zzy("labeled_place", 6);
    public static final UserDataType zzaAb = zzy("here_content", 7);
    public static final Set<UserDataType> zzaAc = Collections.unmodifiableSet(new HashSet(Arrays.asList(zzazZ, zzaAa, zzaAb)));
    public static final zzn CREATOR = new zzn();

    /* JADX INFO: Access modifiers changed from: package-private */
    public UserDataType(int versionCode, String type, int enumValue) {
        zzu.zzcj(type);
        this.zzCY = versionCode;
        this.zzEl = type;
        this.zzaAd = enumValue;
    }

    private static UserDataType zzy(String str, int i) {
        return new UserDataType(0, str, i);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zzn zznVar = CREATOR;
        return 0;
    }

    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object instanceof UserDataType) {
            UserDataType userDataType = (UserDataType) object;
            return this.zzEl.equals(userDataType.zzEl) && this.zzaAd == userDataType.zzaAd;
        }
        return false;
    }

    public int hashCode() {
        return this.zzEl.hashCode();
    }

    public String toString() {
        return this.zzEl;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzn zznVar = CREATOR;
        zzn.zza(this, parcel, flags);
    }
}
