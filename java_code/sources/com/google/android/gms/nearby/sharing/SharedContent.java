package com.google.android.gms.nearby.sharing;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import java.util.Arrays;
/* loaded from: classes.dex */
public class SharedContent implements SafeParcelable {
    public static final Parcelable.Creator<SharedContent> CREATOR = new zzc();
    private final int versionCode;
    @Deprecated
    private String zzaGl;
    private ViewableItem[] zzaGm;
    private LocalContent[] zzaGn;

    private SharedContent() {
        this.versionCode = 2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SharedContent(int versionCode, String uri, ViewableItem[] viewableItems, LocalContent[] localContents) {
        this.versionCode = versionCode;
        this.zzaGl = uri;
        this.zzaGm = viewableItems;
        this.zzaGn = localContents;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof SharedContent) {
            SharedContent sharedContent = (SharedContent) o;
            return zzt.equal(this.zzaGm, sharedContent.zzaGm) && zzt.equal(this.zzaGn, sharedContent.zzaGn) && zzt.equal(this.zzaGl, sharedContent.zzaGl);
        }
        return false;
    }

    public String getUri() {
        return this.zzaGl;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.versionCode;
    }

    public int hashCode() {
        return zzt.hashCode(this.zzaGm, this.zzaGn, this.zzaGl);
    }

    public String toString() {
        return "SharedContent[viewableItems=" + Arrays.toString(this.zzaGm) + ", localContents=" + Arrays.toString(this.zzaGn) + "]";
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzc.zza(this, dest, flags);
    }

    public ViewableItem[] zzxe() {
        return this.zzaGm;
    }

    public LocalContent[] zzxf() {
        return this.zzaGn;
    }
}
