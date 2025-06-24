package com.google.android.gms.games.internal;

import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.games.internal.PopupManager;
/* loaded from: classes.dex */
public final class PopupLocationInfoParcelable implements SafeParcelable {
    public static final PopupLocationInfoParcelableCreator CREATOR = new PopupLocationInfoParcelableCreator();
    private final int zzCY;
    private final Bundle zzaqr;
    private final IBinder zzaqs;

    /* JADX INFO: Access modifiers changed from: package-private */
    public PopupLocationInfoParcelable(int versionCode, Bundle infoBundle, IBinder windowToken) {
        this.zzCY = versionCode;
        this.zzaqr = infoBundle;
        this.zzaqs = windowToken;
    }

    public PopupLocationInfoParcelable(PopupManager.PopupLocationInfo popupLocationInfo) {
        this.zzCY = 1;
        this.zzaqr = popupLocationInfo.zztc();
        this.zzaqs = popupLocationInfo.zzaqv;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    public IBinder getWindowToken() {
        return this.zzaqs;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        PopupLocationInfoParcelableCreator.zza(this, out, flags);
    }

    public Bundle zztc() {
        return this.zzaqr;
    }
}
