package com.google.android.gms.nearby.sharing.internal;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.nearby.sharing.internal.zza;
import com.google.android.gms.nearby.sharing.internal.zzc;
/* loaded from: classes.dex */
public final class ReceiveContentRequest implements SafeParcelable {
    public static final Parcelable.Creator<ReceiveContentRequest> CREATOR = new zzg();
    public String packageName;
    final int versionCode;
    public IBinder zzaGp;
    public zzc zzaGt;
    public zza zzaGu;

    ReceiveContentRequest() {
        this.versionCode = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ReceiveContentRequest(int versionCode, IBinder clientBinder, IBinder contentReceiverAsBinder, String packageName, IBinder callbackAsBinder) {
        this.versionCode = versionCode;
        this.zzaGp = clientBinder;
        this.zzaGu = zza.AbstractBinderC0223zza.zzdh(contentReceiverAsBinder);
        this.packageName = packageName;
        this.zzaGt = zzc.zza.zzdj(callbackAsBinder);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzg.zza(this, dest, flags);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzxa() {
        return this.zzaGt.asBinder();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzxj() {
        if (this.zzaGu == null) {
            return null;
        }
        return this.zzaGu.asBinder();
    }
}
