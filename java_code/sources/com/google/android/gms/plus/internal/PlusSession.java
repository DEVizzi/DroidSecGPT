package com.google.android.gms.plus.internal;

import android.os.Bundle;
import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import java.util.Arrays;
/* loaded from: classes.dex */
public class PlusSession implements SafeParcelable {
    public static final zzh CREATOR = new zzh();
    private final int zzCY;
    private final String zzOx;
    private final String zzTO;
    private final PlusCommonExtras zzaHA;
    private final String[] zzaHu;
    private final String[] zzaHv;
    private final String[] zzaHw;
    private final String zzaHx;
    private final String zzaHy;
    private final String zzaHz;

    /* JADX INFO: Access modifiers changed from: package-private */
    public PlusSession(int versionCode, String accountName, String[] requestedScopes, String[] visibleActions, String[] requiredFeatures, String packageNameForAuth, String callingPackageName, String applicationName, String clientId_DEPRECATED, PlusCommonExtras extras) {
        this.zzCY = versionCode;
        this.zzOx = accountName;
        this.zzaHu = requestedScopes;
        this.zzaHv = visibleActions;
        this.zzaHw = requiredFeatures;
        this.zzaHx = packageNameForAuth;
        this.zzaHy = callingPackageName;
        this.zzTO = applicationName;
        this.zzaHz = clientId_DEPRECATED;
        this.zzaHA = extras;
    }

    public PlusSession(String accountName, String[] requestedScopes, String[] visibleActions, String[] requiredFeatures, String packageNameForAuth, String callingPackageName, String applicationName, PlusCommonExtras extra) {
        this.zzCY = 1;
        this.zzOx = accountName;
        this.zzaHu = requestedScopes;
        this.zzaHv = visibleActions;
        this.zzaHw = requiredFeatures;
        this.zzaHx = packageNameForAuth;
        this.zzaHy = callingPackageName;
        this.zzTO = applicationName;
        this.zzaHz = null;
        this.zzaHA = extra;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object obj) {
        if (obj instanceof PlusSession) {
            PlusSession plusSession = (PlusSession) obj;
            return this.zzCY == plusSession.zzCY && zzt.equal(this.zzOx, plusSession.zzOx) && Arrays.equals(this.zzaHu, plusSession.zzaHu) && Arrays.equals(this.zzaHv, plusSession.zzaHv) && Arrays.equals(this.zzaHw, plusSession.zzaHw) && zzt.equal(this.zzaHx, plusSession.zzaHx) && zzt.equal(this.zzaHy, plusSession.zzaHy) && zzt.equal(this.zzTO, plusSession.zzTO) && zzt.equal(this.zzaHz, plusSession.zzaHz) && zzt.equal(this.zzaHA, plusSession.zzaHA);
        }
        return false;
    }

    public String getAccountName() {
        return this.zzOx;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return zzt.hashCode(Integer.valueOf(this.zzCY), this.zzOx, this.zzaHu, this.zzaHv, this.zzaHw, this.zzaHx, this.zzaHy, this.zzTO, this.zzaHz, this.zzaHA);
    }

    public String toString() {
        return zzt.zzt(this).zzg("versionCode", Integer.valueOf(this.zzCY)).zzg("accountName", this.zzOx).zzg("requestedScopes", this.zzaHu).zzg("visibleActivities", this.zzaHv).zzg("requiredFeatures", this.zzaHw).zzg("packageNameForAuth", this.zzaHx).zzg("callingPackageName", this.zzaHy).zzg("applicationName", this.zzTO).zzg("extra", this.zzaHA.toString()).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzh.zza(this, out, flags);
    }

    public String zzlB() {
        return this.zzTO;
    }

    public String zzxA() {
        return this.zzaHx;
    }

    public String zzxB() {
        return this.zzaHy;
    }

    public String zzxC() {
        return this.zzaHz;
    }

    public PlusCommonExtras zzxD() {
        return this.zzaHA;
    }

    public Bundle zzxE() {
        Bundle bundle = new Bundle();
        bundle.setClassLoader(PlusCommonExtras.class.getClassLoader());
        this.zzaHA.zzy(bundle);
        return bundle;
    }

    public String[] zzxx() {
        return this.zzaHu;
    }

    public String[] zzxy() {
        return this.zzaHv;
    }

    public String[] zzxz() {
        return this.zzaHw;
    }
}
