package com.google.android.gms.nearby.sharing;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
/* loaded from: classes.dex */
public class LocalContent implements SafeParcelable {
    public static final Parcelable.Creator<LocalContent> CREATOR = new zzb();
    private int type;
    private final int versionCode;
    private String zzaGk;

    private LocalContent() {
        this.versionCode = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LocalContent(int versionCode, int type, String contentUri) {
        this.versionCode = versionCode;
        this.type = type;
        this.zzaGk = contentUri;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof LocalContent) {
            LocalContent localContent = (LocalContent) o;
            return zzt.equal(Integer.valueOf(this.type), Integer.valueOf(localContent.type)) && zzt.equal(this.zzaGk, localContent.zzaGk);
        }
        return false;
    }

    public int getType() {
        return this.type;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.versionCode;
    }

    public int hashCode() {
        return zzt.hashCode(Integer.valueOf(this.type), this.zzaGk);
    }

    public String toString() {
        return "LocalContent[contentUri=" + this.zzaGk + ", type=" + (this.type == 1 ? "PUBLIC_CONTENT" : "APP_CONTENT") + "]";
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzb.zza(this, dest, flags);
    }

    public String zzxd() {
        return this.zzaGk;
    }
}
