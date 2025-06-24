package com.google.android.gms.wearable;

import android.net.Uri;
import android.util.Log;
import com.google.android.gms.internal.zzrb;
import com.google.android.gms.internal.zzrn;
/* loaded from: classes.dex */
public class PutDataMapRequest {
    private final DataMap zzaSV = new DataMap();
    private final PutDataRequest zzaSW;

    private PutDataMapRequest(PutDataRequest putDataRequest, DataMap dataMap) {
        this.zzaSW = putDataRequest;
        if (dataMap != null) {
            this.zzaSV.putAll(dataMap);
        }
    }

    public static PutDataMapRequest create(String path) {
        return new PutDataMapRequest(PutDataRequest.create(path), null);
    }

    public static PutDataMapRequest createFromDataMapItem(DataMapItem source) {
        return new PutDataMapRequest(PutDataRequest.zzn(source.getUri()), source.getDataMap());
    }

    public static PutDataMapRequest createWithAutoAppendedId(String pathPrefix) {
        return new PutDataMapRequest(PutDataRequest.createWithAutoAppendedId(pathPrefix), null);
    }

    public PutDataRequest asPutDataRequest() {
        zzrb.zza zza = zzrb.zza(this.zzaSV);
        this.zzaSW.setData(zzrn.zzf(zza.zzaVj));
        int size = zza.zzaVk.size();
        for (int i = 0; i < size; i++) {
            String num = Integer.toString(i);
            Asset asset = zza.zzaVk.get(i);
            if (num == null) {
                throw new IllegalStateException("asset key cannot be null: " + asset);
            }
            if (asset == null) {
                throw new IllegalStateException("asset cannot be null: key=" + num);
            }
            if (Log.isLoggable(DataMap.TAG, 3)) {
                Log.d(DataMap.TAG, "asPutDataRequest: adding asset: " + num + " " + asset);
            }
            this.zzaSW.putAsset(num, asset);
        }
        return this.zzaSW;
    }

    public DataMap getDataMap() {
        return this.zzaSV;
    }

    public Uri getUri() {
        return this.zzaSW.getUri();
    }
}
