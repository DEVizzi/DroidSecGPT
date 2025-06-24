package com.google.android.gms.common.api;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
/* loaded from: classes.dex */
public final class Scope implements SafeParcelable {
    public static final Parcelable.Creator<Scope> CREATOR = new zzj();
    final int zzCY;
    private final String zzXO;

    /* JADX INFO: Access modifiers changed from: package-private */
    public Scope(int versionCode, String scopeUri) {
        zzu.zzh(scopeUri, "scopeUri must not be null or empty");
        this.zzCY = versionCode;
        this.zzXO = scopeUri;
    }

    public Scope(String scopeUri) {
        this(1, scopeUri);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o instanceof Scope) {
            return this.zzXO.equals(((Scope) o).zzXO);
        }
        return false;
    }

    public int hashCode() {
        return this.zzXO.hashCode();
    }

    public String toString() {
        return this.zzXO;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzj.zza(this, dest, flags);
    }

    public String zzmS() {
        return this.zzXO;
    }
}
