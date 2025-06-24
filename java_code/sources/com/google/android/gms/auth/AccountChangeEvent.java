package com.google.android.gms.auth;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.common.internal.zzu;
/* loaded from: classes.dex */
public class AccountChangeEvent implements SafeParcelable {
    public static final Parcelable.Creator<AccountChangeEvent> CREATOR = new zza();
    final int mVersion;
    final String zzOA;
    final long zzOw;
    final String zzOx;
    final int zzOy;
    final int zzOz;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AccountChangeEvent(int version, long id, String accountName, int changeType, int eventIndex, String changeData) {
        this.mVersion = version;
        this.zzOw = id;
        this.zzOx = (String) zzu.zzu(accountName);
        this.zzOy = changeType;
        this.zzOz = eventIndex;
        this.zzOA = changeData;
    }

    public AccountChangeEvent(long id, String accountName, int changeType, int eventIndex, String changeData) {
        this.mVersion = 1;
        this.zzOw = id;
        this.zzOx = (String) zzu.zzu(accountName);
        this.zzOy = changeType;
        this.zzOz = eventIndex;
        this.zzOA = changeData;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object that) {
        if (that == this) {
            return true;
        }
        if (that instanceof AccountChangeEvent) {
            AccountChangeEvent accountChangeEvent = (AccountChangeEvent) that;
            return this.mVersion == accountChangeEvent.mVersion && this.zzOw == accountChangeEvent.zzOw && zzt.equal(this.zzOx, accountChangeEvent.zzOx) && this.zzOy == accountChangeEvent.zzOy && this.zzOz == accountChangeEvent.zzOz && zzt.equal(this.zzOA, accountChangeEvent.zzOA);
        }
        return false;
    }

    public String getAccountName() {
        return this.zzOx;
    }

    public String getChangeData() {
        return this.zzOA;
    }

    public int getChangeType() {
        return this.zzOy;
    }

    public int getEventIndex() {
        return this.zzOz;
    }

    public int hashCode() {
        return zzt.hashCode(Integer.valueOf(this.mVersion), Long.valueOf(this.zzOw), this.zzOx, Integer.valueOf(this.zzOy), Integer.valueOf(this.zzOz), this.zzOA);
    }

    public String toString() {
        String str = "UNKNOWN";
        switch (this.zzOy) {
            case 1:
                str = "ADDED";
                break;
            case 2:
                str = "REMOVED";
                break;
            case 3:
                str = "RENAMED_FROM";
                break;
            case 4:
                str = "RENAMED_TO";
                break;
        }
        return "AccountChangeEvent {accountName = " + this.zzOx + ", changeType = " + str + ", changeData = " + this.zzOA + ", eventIndex = " + this.zzOz + "}";
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zza.zza(this, dest, flags);
    }
}
