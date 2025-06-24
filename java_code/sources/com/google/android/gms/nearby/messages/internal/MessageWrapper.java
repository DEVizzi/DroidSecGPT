package com.google.android.gms.nearby.messages.internal;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.nearby.messages.Message;
/* loaded from: classes.dex */
public class MessageWrapper implements SafeParcelable {
    public static final zze CREATOR = new zze();
    final int versionCode;
    public final Message zzaFZ;

    /* JADX INFO: Access modifiers changed from: package-private */
    public MessageWrapper(int versionCode, Message message) {
        this.versionCode = versionCode;
        this.zzaFZ = (Message) zzu.zzu(message);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zze zzeVar = CREATOR;
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zze zzeVar = CREATOR;
        zze.zza(this, out, flags);
    }
}
