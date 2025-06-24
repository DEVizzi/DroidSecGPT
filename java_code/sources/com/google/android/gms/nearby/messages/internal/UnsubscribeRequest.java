package com.google.android.gms.nearby.messages.internal;

import android.app.PendingIntent;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.nearby.messages.internal.zza;
import com.google.android.gms.nearby.messages.internal.zzb;
/* loaded from: classes.dex */
public final class UnsubscribeRequest implements SafeParcelable {
    public static final Parcelable.Creator<UnsubscribeRequest> CREATOR = new zzl();
    final int zzCY;
    public final zzb zzaGd;
    public final String zzaGe;
    public final zza zzaGf;
    public final PendingIntent zzaGh;
    public final int zzaGi;
    public final String zzayp;

    /* JADX INFO: Access modifiers changed from: package-private */
    public UnsubscribeRequest(int versionCode, IBinder messageListener, IBinder callbackAsBinder, PendingIntent pendingIntent, int messageListenerKey, String zeroPartyPackageName, String realClientPackageName) {
        this.zzCY = versionCode;
        this.zzaGf = zza.AbstractBinderC0219zza.zzdd(messageListener);
        this.zzaGd = zzb.zza.zzde(callbackAsBinder);
        this.zzaGh = pendingIntent;
        this.zzaGi = messageListenerKey;
        this.zzayp = zeroPartyPackageName;
        this.zzaGe = realClientPackageName;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzl.zza(this, dest, flags);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzxa() {
        return this.zzaGd.asBinder();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzxb() {
        if (this.zzaGf == null) {
            return null;
        }
        return this.zzaGf.asBinder();
    }
}
