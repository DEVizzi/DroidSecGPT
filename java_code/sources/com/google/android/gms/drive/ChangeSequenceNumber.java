package com.google.android.gms.drive;

import android.os.Parcel;
import android.os.Parcelable;
import android.util.Base64;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.drive.internal.zzaq;
import com.google.android.gms.internal.zzrn;
/* loaded from: classes.dex */
public class ChangeSequenceNumber implements SafeParcelable {
    public static final Parcelable.Creator<ChangeSequenceNumber> CREATOR = new zza();
    final int zzCY;
    final long zzacN;
    final long zzacO;
    final long zzacP;
    private volatile String zzacQ = null;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ChangeSequenceNumber(int versionCode, long sequenceNumber, long databaseInstanceId, long accountId) {
        zzu.zzV(sequenceNumber != -1);
        zzu.zzV(databaseInstanceId != -1);
        zzu.zzV(accountId != -1);
        this.zzCY = versionCode;
        this.zzacN = sequenceNumber;
        this.zzacO = databaseInstanceId;
        this.zzacP = accountId;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public final String encodeToString() {
        if (this.zzacQ == null) {
            this.zzacQ = "ChangeSequenceNumber:" + Base64.encodeToString(zzpb(), 10);
        }
        return this.zzacQ;
    }

    public boolean equals(Object obj) {
        if (obj instanceof ChangeSequenceNumber) {
            ChangeSequenceNumber changeSequenceNumber = (ChangeSequenceNumber) obj;
            return changeSequenceNumber.zzacO == this.zzacO && changeSequenceNumber.zzacP == this.zzacP && changeSequenceNumber.zzacN == this.zzacN;
        }
        return false;
    }

    public int hashCode() {
        return (String.valueOf(this.zzacN) + String.valueOf(this.zzacO) + String.valueOf(this.zzacP)).hashCode();
    }

    public String toString() {
        return encodeToString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zza.zza(this, out, flags);
    }

    final byte[] zzpb() {
        zzaq zzaqVar = new zzaq();
        zzaqVar.versionCode = this.zzCY;
        zzaqVar.zzafU = this.zzacN;
        zzaqVar.zzafV = this.zzacO;
        zzaqVar.zzafW = this.zzacP;
        return zzrn.zzf(zzaqVar);
    }
}
