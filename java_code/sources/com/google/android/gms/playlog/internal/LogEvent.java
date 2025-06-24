package com.google.android.gms.playlog.internal;

import android.os.Bundle;
import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class LogEvent implements SafeParcelable {
    public static final zzc CREATOR = new zzc();
    public final String tag;
    public final int versionCode;
    public final long zzaGF;
    public final byte[] zzaGG;
    public final Bundle zzaGH;

    /* JADX INFO: Access modifiers changed from: package-private */
    public LogEvent(int versionCode, long eventTime, String tag, byte[] sourceExtensionBytes, Bundle keyValuePairs) {
        this.versionCode = versionCode;
        this.zzaGF = eventTime;
        this.tag = tag;
        this.zzaGG = sourceExtensionBytes;
        this.zzaGH = keyValuePairs;
    }

    public LogEvent(long eventTime, String tag, byte[] sourceExtensionBytes, String... extras) {
        this.versionCode = 1;
        this.zzaGF = eventTime;
        this.tag = tag;
        this.zzaGG = sourceExtensionBytes;
        this.zzaGH = zzd(extras);
    }

    private static Bundle zzd(String... strArr) {
        Bundle bundle = null;
        if (strArr != null) {
            if (strArr.length % 2 != 0) {
                throw new IllegalArgumentException("extras must have an even number of elements");
            }
            int length = strArr.length / 2;
            if (length != 0) {
                bundle = new Bundle(length);
                for (int i = 0; i < length; i++) {
                    bundle.putString(strArr[i * 2], strArr[(i * 2) + 1]);
                }
            }
        }
        return bundle;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("tag=").append(this.tag).append(",");
        sb.append("eventTime=").append(this.zzaGF).append(",");
        if (this.zzaGH != null && !this.zzaGH.isEmpty()) {
            sb.append("keyValues=");
            for (String str : this.zzaGH.keySet()) {
                sb.append("(").append(str).append(",");
                sb.append(this.zzaGH.getString(str)).append(")");
                sb.append(" ");
            }
        }
        return sb.toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzc.zza(this, out, flags);
    }
}
