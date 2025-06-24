package com.google.android.gms.drive.events;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.drive.DriveId;
/* loaded from: classes.dex */
public final class ProgressEvent implements DriveEvent {
    public static final Parcelable.Creator<ProgressEvent> CREATOR = new zzh();
    final int zzCY;
    final int zzSq;
    final DriveId zzacT;
    final long zzaeg;
    final long zzaeh;
    final int zzwS;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProgressEvent(int versionCode, DriveId driveId, int status, long bytesTransferred, long totalBytes, int type) {
        this.zzCY = versionCode;
        this.zzacT = driveId;
        this.zzwS = status;
        this.zzaeg = bytesTransferred;
        this.zzaeh = totalBytes;
        this.zzSq = type;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        if (o == null || o.getClass() != getClass()) {
            return false;
        }
        if (o != this) {
            ProgressEvent progressEvent = (ProgressEvent) o;
            return zzt.equal(this.zzacT, progressEvent.zzacT) && this.zzwS == progressEvent.zzwS && this.zzaeg == progressEvent.zzaeg && this.zzaeh == progressEvent.zzaeh;
        }
        return true;
    }

    @Override // com.google.android.gms.drive.events.DriveEvent
    public int getType() {
        return this.zzSq;
    }

    public int hashCode() {
        return zzt.hashCode(this.zzacT, Integer.valueOf(this.zzwS), Long.valueOf(this.zzaeg), Long.valueOf(this.zzaeh));
    }

    public String toString() {
        return String.format("ProgressEvent[DriveId: %s, status: %d, bytes transferred: %d, total bytes: %d]", this.zzacT, Integer.valueOf(this.zzwS), Long.valueOf(this.zzaeg), Long.valueOf(this.zzaeh));
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzh.zza(this, dest, flags);
    }
}
