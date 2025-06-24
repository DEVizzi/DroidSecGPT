package com.google.android.gms.wearable.internal;

import android.content.IntentFilter;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.wearable.internal.zzas;
/* loaded from: classes.dex */
public class AddListenerRequest implements SafeParcelable {
    public static final Parcelable.Creator<AddListenerRequest> CREATOR = new zzb();
    final int zzCY;
    public final zzas zzaTq;
    public final IntentFilter[] zzaTr;
    public final String zzaTs;
    public final String zzaTt;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AddListenerRequest(int versionCode, IBinder listener, IntentFilter[] filters, String channelToken, String capability) {
        this.zzCY = versionCode;
        if (listener != null) {
            this.zzaTq = zzas.zza.zzdP(listener);
        } else {
            this.zzaTq = null;
        }
        this.zzaTr = filters;
        this.zzaTs = channelToken;
        this.zzaTt = capability;
    }

    public AddListenerRequest(zzbl stub) {
        this.zzCY = 1;
        this.zzaTq = stub;
        this.zzaTr = stub.zzBh();
        this.zzaTs = stub.zzBi();
        this.zzaTt = stub.zzBj();
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzb.zza(this, dest, flags);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzAT() {
        if (this.zzaTq == null) {
            return null;
        }
        return this.zzaTq.asBinder();
    }
}
