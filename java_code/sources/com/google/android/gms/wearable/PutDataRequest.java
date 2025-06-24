package com.google.android.gms.wearable;

import android.net.Uri;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import android.util.Log;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.wearable.internal.DataItemAssetParcelable;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
/* loaded from: classes.dex */
public class PutDataRequest implements SafeParcelable {
    public static final String WEAR_URI_SCHEME = "wear";
    private final Uri mUri;
    final int zzCY;
    private final Bundle zzaSY;
    private byte[] zzauL;
    public static final Parcelable.Creator<PutDataRequest> CREATOR = new zzf();
    private static final Random zzaSX = new SecureRandom();

    private PutDataRequest(int versionCode, Uri uri) {
        this(versionCode, uri, new Bundle(), null);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public PutDataRequest(int versionCode, Uri uri, Bundle assets, byte[] data) {
        this.zzCY = versionCode;
        this.mUri = uri;
        this.zzaSY = assets;
        this.zzaSY.setClassLoader(DataItemAssetParcelable.class.getClassLoader());
        this.zzauL = data;
    }

    public static PutDataRequest create(String path) {
        return zzn(zzfg(path));
    }

    public static PutDataRequest createFromDataItem(DataItem source) {
        PutDataRequest zzn = zzn(source.getUri());
        for (Map.Entry<String, DataItemAsset> entry : source.getAssets().entrySet()) {
            if (entry.getValue().getId() == null) {
                throw new IllegalStateException("Cannot create an asset for a put request without a digest: " + entry.getKey());
            }
            zzn.putAsset(entry.getKey(), Asset.createFromRef(entry.getValue().getId()));
        }
        zzn.setData(source.getData());
        return zzn;
    }

    public static PutDataRequest createWithAutoAppendedId(String pathPrefix) {
        StringBuilder sb = new StringBuilder(pathPrefix);
        if (!pathPrefix.endsWith("/")) {
            sb.append("/");
        }
        sb.append("PN").append(zzaSX.nextLong());
        return new PutDataRequest(1, zzfg(sb.toString()));
    }

    private static Uri zzfg(String str) {
        if (TextUtils.isEmpty(str)) {
            throw new IllegalArgumentException("An empty path was supplied.");
        }
        if (str.startsWith("/")) {
            if (str.startsWith("//")) {
                throw new IllegalArgumentException("A path must start with a single / .");
            }
            return new Uri.Builder().scheme(WEAR_URI_SCHEME).path(str).build();
        }
        throw new IllegalArgumentException("A path must start with a single / .");
    }

    public static PutDataRequest zzn(Uri uri) {
        return new PutDataRequest(1, uri);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public Asset getAsset(String key) {
        return (Asset) this.zzaSY.getParcelable(key);
    }

    public Map<String, Asset> getAssets() {
        HashMap hashMap = new HashMap();
        for (String str : this.zzaSY.keySet()) {
            hashMap.put(str, (Asset) this.zzaSY.getParcelable(str));
        }
        return Collections.unmodifiableMap(hashMap);
    }

    public byte[] getData() {
        return this.zzauL;
    }

    public Uri getUri() {
        return this.mUri;
    }

    public boolean hasAsset(String key) {
        return this.zzaSY.containsKey(key);
    }

    public PutDataRequest putAsset(String key, Asset value) {
        zzu.zzu(key);
        zzu.zzu(value);
        this.zzaSY.putParcelable(key, value);
        return this;
    }

    public PutDataRequest removeAsset(String key) {
        this.zzaSY.remove(key);
        return this;
    }

    public PutDataRequest setData(byte[] data) {
        this.zzauL = data;
        return this;
    }

    public String toString() {
        return toString(Log.isLoggable(DataMap.TAG, 3));
    }

    public String toString(boolean verbose) {
        StringBuilder sb = new StringBuilder("PutDataRequest[");
        sb.append("dataSz=" + (this.zzauL == null ? "null" : Integer.valueOf(this.zzauL.length)));
        sb.append(", numAssets=" + this.zzaSY.size());
        sb.append(", uri=" + this.mUri);
        if (!verbose) {
            sb.append("]");
            return sb.toString();
        }
        sb.append("]\n  assets: ");
        for (String str : this.zzaSY.keySet()) {
            sb.append("\n    " + str + ": " + this.zzaSY.getParcelable(str));
        }
        sb.append("\n  ]");
        return sb.toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzf.zza(this, dest, flags);
    }

    public Bundle zzAR() {
        return this.zzaSY;
    }
}
