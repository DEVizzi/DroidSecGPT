package com.google.android.gms.nearby.sharing.internal;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.nearby.sharing.SharedContent;
import com.google.android.gms.nearby.sharing.internal.zzb;
import com.google.android.gms.nearby.sharing.internal.zzc;
import java.util.List;
/* loaded from: classes.dex */
public final class ProvideContentRequest implements SafeParcelable {
    public static final Parcelable.Creator<ProvideContentRequest> CREATOR = new zzf();
    final int versionCode;
    public IBinder zzaGp;
    public zzb zzaGq;
    @Deprecated
    public List<SharedContent> zzaGr;
    public long zzaGs;
    public zzc zzaGt;

    ProvideContentRequest() {
        this.versionCode = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProvideContentRequest(int versionCode, IBinder clientBinder, IBinder contentProviderAsBinder, List<SharedContent> content, long activityId, IBinder callbackAsBinder) {
        this.versionCode = versionCode;
        this.zzaGp = clientBinder;
        this.zzaGq = zzb.zza.zzdi(contentProviderAsBinder);
        this.zzaGr = content;
        this.zzaGs = activityId;
        this.zzaGt = zzc.zza.zzdj(callbackAsBinder);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzf.zza(this, dest, flags);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzxa() {
        return this.zzaGt.asBinder();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzxi() {
        if (this.zzaGq == null) {
            return null;
        }
        return this.zzaGq.asBinder();
    }
}
