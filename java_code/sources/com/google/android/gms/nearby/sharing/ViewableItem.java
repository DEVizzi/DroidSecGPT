package com.google.android.gms.nearby.sharing;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import java.util.Arrays;
/* loaded from: classes.dex */
public class ViewableItem implements SafeParcelable {
    public static final Parcelable.Creator<ViewableItem> CREATOR = new zzf();
    private final int versionCode;
    private String[] zzaGo;

    private ViewableItem() {
        this.versionCode = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ViewableItem(int versionCode, String[] uris) {
        this.versionCode = versionCode;
        this.zzaGo = uris;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof ViewableItem) {
            return zzt.equal(this.zzaGo, ((ViewableItem) o).zzaGo);
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.versionCode;
    }

    public int hashCode() {
        return zzt.hashCode(this.zzaGo);
    }

    public String toString() {
        return "ViewableItem[uris=" + Arrays.toString(this.zzaGo) + "]";
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzf.zza(this, dest, flags);
    }

    public String[] zzxg() {
        return this.zzaGo;
    }
}
