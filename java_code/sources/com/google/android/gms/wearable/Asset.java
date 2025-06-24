package com.google.android.gms.wearable;

import android.net.Uri;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
/* loaded from: classes.dex */
public class Asset implements SafeParcelable {
    public static final Parcelable.Creator<Asset> CREATOR = new zzc();
    public Uri uri;
    final int zzCY;
    private String zzaSM;
    public ParcelFileDescriptor zzaSN;
    private byte[] zzauL;

    /* JADX INFO: Access modifiers changed from: package-private */
    public Asset(int versionCode, byte[] data, String digest, ParcelFileDescriptor fd, Uri uri) {
        this.zzCY = versionCode;
        this.zzauL = data;
        this.zzaSM = digest;
        this.zzaSN = fd;
        this.uri = uri;
    }

    public static Asset createFromBytes(byte[] assetData) {
        if (assetData == null) {
            throw new IllegalArgumentException("Asset data cannot be null");
        }
        return new Asset(1, assetData, null, null, null);
    }

    public static Asset createFromFd(ParcelFileDescriptor fd) {
        if (fd == null) {
            throw new IllegalArgumentException("Asset fd cannot be null");
        }
        return new Asset(1, null, null, fd, null);
    }

    public static Asset createFromRef(String digest) {
        if (digest == null) {
            throw new IllegalArgumentException("Asset digest cannot be null");
        }
        return new Asset(1, null, digest, null, null);
    }

    public static Asset createFromUri(Uri uri) {
        if (uri == null) {
            throw new IllegalArgumentException("Asset uri cannot be null");
        }
        return new Asset(1, null, null, null, uri);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o instanceof Asset) {
            Asset asset = (Asset) o;
            return zzt.equal(this.zzauL, asset.zzauL) && zzt.equal(this.zzaSM, asset.zzaSM) && zzt.equal(this.zzaSN, asset.zzaSN) && zzt.equal(this.uri, asset.uri);
        }
        return false;
    }

    public byte[] getData() {
        return this.zzauL;
    }

    public String getDigest() {
        return this.zzaSM;
    }

    public ParcelFileDescriptor getFd() {
        return this.zzaSN;
    }

    public Uri getUri() {
        return this.uri;
    }

    public int hashCode() {
        return zzt.hashCode(this.zzauL, this.zzaSM, this.zzaSN, this.uri);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Asset[@");
        sb.append(Integer.toHexString(hashCode()));
        if (this.zzaSM == null) {
            sb.append(", nodigest");
        } else {
            sb.append(", ");
            sb.append(this.zzaSM);
        }
        if (this.zzauL != null) {
            sb.append(", size=");
            sb.append(this.zzauL.length);
        }
        if (this.zzaSN != null) {
            sb.append(", fd=");
            sb.append(this.zzaSN);
        }
        if (this.uri != null) {
            sb.append(", uri=");
            sb.append(this.uri);
        }
        sb.append("]");
        return sb.toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzc.zza(this, dest, flags | 1);
    }
}
