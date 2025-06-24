package com.google.android.gms.auth.api.proxy;

import android.app.PendingIntent;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class ProxyResponse implements SafeParcelable {
    public static final Parcelable.Creator<ProxyResponse> CREATOR = new zzc();
    final int versionCode;
    public final byte[] zzPs;
    final Bundle zzPt;
    public final int zzPu;
    public final PendingIntent zzPv;
    public final int zzPw;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProxyResponse(int version, int googlePlayServicesStatusCode, PendingIntent recoveryAction, int httpCode, Bundle headers, byte[] body) {
        this.versionCode = version;
        this.zzPu = googlePlayServicesStatusCode;
        this.zzPw = httpCode;
        this.zzPt = headers;
        this.zzPs = body;
        this.zzPv = recoveryAction;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzc.zza(this, parcel, flags);
    }
}
