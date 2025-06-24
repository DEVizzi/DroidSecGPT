package com.google.android.gms.wearable.internal;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.wearable.internal.zzas;
/* loaded from: classes.dex */
public class RemoveListenerRequest implements SafeParcelable {
    public static final Parcelable.Creator<RemoveListenerRequest> CREATOR = new zzbc();
    final int zzCY;
    public final zzas zzaTq;

    /* JADX INFO: Access modifiers changed from: package-private */
    public RemoveListenerRequest(int versionCode, IBinder listener) {
        this.zzCY = versionCode;
        if (listener != null) {
            this.zzaTq = zzas.zza.zzdP(listener);
        } else {
            this.zzaTq = null;
        }
    }

    public RemoveListenerRequest(zzas listener) {
        this.zzCY = 1;
        this.zzaTq = listener;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzbc.zza(this, dest, flags);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzAT() {
        if (this.zzaTq == null) {
            return null;
        }
        return this.zzaTq.asBinder();
    }
}
