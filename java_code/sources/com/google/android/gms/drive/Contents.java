package com.google.android.gms.drive;

import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
/* loaded from: classes.dex */
public class Contents implements SafeParcelable {
    public static final Parcelable.Creator<Contents> CREATOR = new zzb();
    final int zzCY;
    final ParcelFileDescriptor zzYZ;
    final int zzacR;
    final int zzacS;
    final DriveId zzacT;
    final boolean zzacU;

    /* JADX INFO: Access modifiers changed from: package-private */
    public Contents(int versionCode, ParcelFileDescriptor parcelFileDescriptor, int requestId, int mode, DriveId driveId, boolean validForConflictDetection) {
        this.zzCY = versionCode;
        this.zzYZ = parcelFileDescriptor;
        this.zzacR = requestId;
        this.zzacS = mode;
        this.zzacT = driveId;
        this.zzacU = validForConflictDetection;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public DriveId getDriveId() {
        return this.zzacT;
    }

    public InputStream getInputStream() {
        return new FileInputStream(this.zzYZ.getFileDescriptor());
    }

    public int getMode() {
        return this.zzacS;
    }

    public OutputStream getOutputStream() {
        return new FileOutputStream(this.zzYZ.getFileDescriptor());
    }

    public ParcelFileDescriptor getParcelFileDescriptor() {
        return this.zzYZ;
    }

    public int getRequestId() {
        return this.zzacR;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzb.zza(this, dest, flags);
    }

    public boolean zzpc() {
        return this.zzacU;
    }
}
