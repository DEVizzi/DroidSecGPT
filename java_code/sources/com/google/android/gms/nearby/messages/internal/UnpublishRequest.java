package com.google.android.gms.nearby.messages.internal;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.nearby.messages.internal.zzb;
/* loaded from: classes.dex */
public final class UnpublishRequest implements SafeParcelable {
    public static final Parcelable.Creator<UnpublishRequest> CREATOR = new zzk();
    final int zzCY;
    public final MessageWrapper zzaGb;
    public final zzb zzaGd;
    public final String zzaGe;
    public final String zzayp;

    /* JADX INFO: Access modifiers changed from: package-private */
    public UnpublishRequest(int versionCode, MessageWrapper messageWrapper, IBinder callbackAsBinder, String zeroPartyPackageName, String realClientPackageName) {
        this.zzCY = versionCode;
        this.zzaGb = messageWrapper;
        this.zzaGd = zzb.zza.zzde(callbackAsBinder);
        this.zzayp = zeroPartyPackageName;
        this.zzaGe = realClientPackageName;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzk.zza(this, dest, flags);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzxa() {
        return this.zzaGd.asBinder();
    }
}
