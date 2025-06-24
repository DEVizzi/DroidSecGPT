package com.google.android.gms.location.places.personalized;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.location.places.personalized.internal.TestDataImpl;
import java.util.List;
/* loaded from: classes.dex */
public class PlaceUserData implements SafeParcelable {
    public static final zze CREATOR = new zze();
    final int zzCY;
    private final String zzOx;
    private final List<TestDataImpl> zzaBj;
    private final List<PlaceAlias> zzaBk;
    private final List<HereContent> zzaBl;
    private final String zzazK;

    /* JADX INFO: Access modifiers changed from: package-private */
    public PlaceUserData(int versionCode, String accountName, String placeId, List<TestDataImpl> testDataImpls, List<PlaceAlias> placeAliases, List<HereContent> hereContents) {
        this.zzCY = versionCode;
        this.zzOx = accountName;
        this.zzazK = placeId;
        this.zzaBj = testDataImpls;
        this.zzaBk = placeAliases;
        this.zzaBl = hereContents;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zze zzeVar = CREATOR;
        return 0;
    }

    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object instanceof PlaceUserData) {
            PlaceUserData placeUserData = (PlaceUserData) object;
            return this.zzOx.equals(placeUserData.zzOx) && this.zzazK.equals(placeUserData.zzazK) && this.zzaBj.equals(placeUserData.zzaBj) && this.zzaBk.equals(placeUserData.zzaBk) && this.zzaBl.equals(placeUserData.zzaBl);
        }
        return false;
    }

    public String getPlaceId() {
        return this.zzazK;
    }

    public int hashCode() {
        return zzt.hashCode(this.zzOx, this.zzazK, this.zzaBj, this.zzaBk, this.zzaBl);
    }

    public String toString() {
        return zzt.zzt(this).zzg("accountName", this.zzOx).zzg("placeId", this.zzazK).zzg("testDataImpls", this.zzaBj).zzg("placeAliases", this.zzaBk).zzg("hereContents", this.zzaBl).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zze zzeVar = CREATOR;
        zze.zza(this, parcel, flags);
    }

    public String zzvb() {
        return this.zzOx;
    }

    public List<PlaceAlias> zzvc() {
        return this.zzaBk;
    }

    public List<HereContent> zzvd() {
        return this.zzaBl;
    }

    public List<TestDataImpl> zzve() {
        return this.zzaBj;
    }
}
