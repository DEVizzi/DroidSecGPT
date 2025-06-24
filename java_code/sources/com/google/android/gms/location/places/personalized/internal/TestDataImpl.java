package com.google.android.gms.location.places.personalized.internal;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.location.places.personalized.zzf;
/* loaded from: classes.dex */
public class TestDataImpl extends zzf implements SafeParcelable {
    public static final zza CREATOR = new zza();
    final int zzCY;
    private final String zzaBm;

    /* JADX INFO: Access modifiers changed from: package-private */
    public TestDataImpl(int versionCode, String testName) {
        this.zzCY = versionCode;
        this.zzaBm = testName;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zza zzaVar = CREATOR;
        return 0;
    }

    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object instanceof TestDataImpl) {
            return this.zzaBm.equals(((TestDataImpl) object).zzaBm);
        }
        return false;
    }

    public int hashCode() {
        return this.zzaBm.hashCode();
    }

    public String toString() {
        return zzt.zzt(this).zzg("testName", this.zzaBm).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zza zzaVar = CREATOR;
        zza.zza(this, parcel, flags);
    }

    public String zzvf() {
        return this.zzaBm;
    }
}
