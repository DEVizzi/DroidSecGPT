package com.google.android.gms.cast;

import com.google.android.gms.cast.internal.zzf;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.internal.zzlh;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
/* loaded from: classes.dex */
public class MediaQueueItem {
    public static final double DEFAULT_PLAYBACK_DURATION = Double.POSITIVE_INFINITY;
    public static final int INVALID_ITEM_ID = 0;
    private JSONObject zzRJ;
    private MediaInfo zzRS;
    private int zzRT;
    private boolean zzRU;
    private double zzRV;
    private double zzRW;
    private double zzRX;
    private long[] zzRY;

    /* loaded from: classes.dex */
    public static class Builder {
        private final MediaQueueItem zzRZ;

        public Builder(MediaInfo media) throws IllegalArgumentException {
            this.zzRZ = new MediaQueueItem(media);
        }

        public Builder(MediaQueueItem item) throws IllegalArgumentException {
            this.zzRZ = new MediaQueueItem();
        }

        public Builder(JSONObject json) throws JSONException {
            this.zzRZ = new MediaQueueItem(json);
        }

        public MediaQueueItem build() {
            this.zzRZ.zzlq();
            return this.zzRZ;
        }

        public Builder clearItemId() {
            this.zzRZ.zzaC(0);
            return this;
        }

        public Builder setActiveTrackIds(long[] activeTrackIds) {
            this.zzRZ.zza(activeTrackIds);
            return this;
        }

        public Builder setAutoplay(boolean autoplay) {
            this.zzRZ.zzP(autoplay);
            return this;
        }

        public Builder setCustomData(JSONObject customData) {
            this.zzRZ.setCustomData(customData);
            return this;
        }

        public Builder setPreloadTime(double preloadTime) throws IllegalArgumentException {
            this.zzRZ.zzc(preloadTime);
            return this;
        }

        public Builder setStartTime(double startTime) throws IllegalArgumentException {
            this.zzRZ.zzb(startTime);
            return this;
        }
    }

    private MediaQueueItem(MediaInfo media) throws IllegalArgumentException {
        this.zzRT = 0;
        this.zzRU = true;
        this.zzRW = Double.POSITIVE_INFINITY;
        if (media == null) {
            throw new IllegalArgumentException("media cannot be null.");
        }
        this.zzRS = media;
    }

    private MediaQueueItem(MediaQueueItem item) throws IllegalArgumentException {
        this.zzRT = 0;
        this.zzRU = true;
        this.zzRW = Double.POSITIVE_INFINITY;
        this.zzRS = item.getMedia();
        if (this.zzRS == null) {
            throw new IllegalArgumentException("media cannot be null.");
        }
        this.zzRT = item.getItemId();
        this.zzRU = item.getAutoplay();
        this.zzRV = item.getStartTime();
        this.zzRW = item.zzlr();
        this.zzRX = item.getPreloadTime();
        this.zzRY = item.getActiveTrackIds();
        this.zzRJ = item.getCustomData();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MediaQueueItem(JSONObject json) throws JSONException {
        this.zzRT = 0;
        this.zzRU = true;
        this.zzRW = Double.POSITIVE_INFINITY;
        zzg(json);
    }

    public boolean equals(Object other) {
        boolean z = true;
        if (this == other) {
            return true;
        }
        if (other instanceof MediaQueueItem) {
            MediaQueueItem mediaQueueItem = (MediaQueueItem) other;
            if ((this.zzRJ == null) == (mediaQueueItem.zzRJ == null)) {
                if (this.zzRJ == null || mediaQueueItem.zzRJ == null || zzlh.zzd(this.zzRJ, mediaQueueItem.zzRJ)) {
                    if (!zzf.zza(this.zzRS, mediaQueueItem.zzRS) || this.zzRT != mediaQueueItem.zzRT || this.zzRU != mediaQueueItem.zzRU || this.zzRV != mediaQueueItem.zzRV || this.zzRW != mediaQueueItem.zzRW || this.zzRX != mediaQueueItem.zzRX || !zzf.zza(this.zzRY, mediaQueueItem.zzRY)) {
                        z = false;
                    }
                    return z;
                }
                return false;
            }
            return false;
        }
        return false;
    }

    public long[] getActiveTrackIds() {
        return this.zzRY;
    }

    public boolean getAutoplay() {
        return this.zzRU;
    }

    public JSONObject getCustomData() {
        return this.zzRJ;
    }

    public int getItemId() {
        return this.zzRT;
    }

    public MediaInfo getMedia() {
        return this.zzRS;
    }

    public double getPreloadTime() {
        return this.zzRX;
    }

    public double getStartTime() {
        return this.zzRV;
    }

    public int hashCode() {
        return zzt.hashCode(this.zzRS, Integer.valueOf(this.zzRT), Boolean.valueOf(this.zzRU), Double.valueOf(this.zzRV), Double.valueOf(this.zzRW), Double.valueOf(this.zzRX), this.zzRY, String.valueOf(this.zzRJ));
    }

    void setCustomData(JSONObject customData) {
        this.zzRJ = customData;
    }

    public JSONObject toJson() {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("media", this.zzRS.toJson());
            if (this.zzRT != 0) {
                jSONObject.put("itemId", this.zzRT);
            }
            jSONObject.put("autoplay", this.zzRU);
            jSONObject.put("startTime", this.zzRV);
            if (this.zzRW != Double.POSITIVE_INFINITY) {
                jSONObject.put("playbackDuration", this.zzRW);
            }
            jSONObject.put("preloadTime", this.zzRX);
            if (this.zzRY != null && this.zzRY.length > 0) {
                JSONArray jSONArray = new JSONArray();
                for (long j : this.zzRY) {
                    jSONArray.put(j);
                }
                jSONObject.put("activeTrackIds", jSONArray);
            }
            if (this.zzRJ != null) {
                jSONObject.put("customData", this.zzRJ);
            }
        } catch (JSONException e) {
        }
        return jSONObject;
    }

    void zzP(boolean z) {
        this.zzRU = z;
    }

    void zza(long[] jArr) {
        this.zzRY = jArr;
    }

    void zzaC(int i) {
        this.zzRT = i;
    }

    void zzb(double d) throws IllegalArgumentException {
        if (Double.isNaN(d) || d < 0.0d) {
            throw new IllegalArgumentException("startTime cannot be negative or NaN.");
        }
        this.zzRV = d;
    }

    void zzc(double d) throws IllegalArgumentException {
        if (Double.isNaN(d) || d < 0.0d) {
            throw new IllegalArgumentException("preloadTime cannot be negative or NaN.");
        }
        this.zzRX = d;
    }

    public boolean zzg(JSONObject jSONObject) throws JSONException {
        boolean z;
        boolean z2;
        long[] jArr;
        boolean z3;
        int i;
        if (jSONObject.has("media")) {
            this.zzRS = new MediaInfo(jSONObject.getJSONObject("media"));
            z = true;
        } else {
            z = false;
        }
        if (jSONObject.has("itemId") && this.zzRT != (i = jSONObject.getInt("itemId"))) {
            this.zzRT = i;
            z = true;
        }
        if (jSONObject.has("autoplay") && this.zzRU != (z3 = jSONObject.getBoolean("autoplay"))) {
            this.zzRU = z3;
            z = true;
        }
        if (jSONObject.has("startTime")) {
            double d = jSONObject.getDouble("startTime");
            if (Math.abs(d - this.zzRV) > 1.0E-7d) {
                this.zzRV = d;
                z = true;
            }
        }
        if (jSONObject.has("playbackDuration")) {
            double d2 = jSONObject.getDouble("playbackDuration");
            if (Math.abs(d2 - this.zzRW) > 1.0E-7d) {
                this.zzRW = d2;
                z = true;
            }
        }
        if (jSONObject.has("preloadTime")) {
            double d3 = jSONObject.getDouble("preloadTime");
            if (Math.abs(d3 - this.zzRX) > 1.0E-7d) {
                this.zzRX = d3;
                z = true;
            }
        }
        if (jSONObject.has("activeTrackIds")) {
            JSONArray jSONArray = jSONObject.getJSONArray("activeTrackIds");
            int length = jSONArray.length();
            long[] jArr2 = new long[length];
            for (int i2 = 0; i2 < length; i2++) {
                jArr2[i2] = jSONArray.getLong(i2);
            }
            if (this.zzRY == null) {
                jArr = jArr2;
                z2 = true;
            } else if (this.zzRY.length == length) {
                int i3 = 0;
                while (true) {
                    if (i3 >= length) {
                        z2 = false;
                        jArr = jArr2;
                        break;
                    } else if (this.zzRY[i3] != jArr2[i3]) {
                        jArr = jArr2;
                        z2 = true;
                        break;
                    } else {
                        i3++;
                    }
                }
            } else {
                jArr = jArr2;
                z2 = true;
            }
        } else {
            z2 = false;
            jArr = null;
        }
        if (z2) {
            this.zzRY = jArr;
            z = true;
        }
        if (jSONObject.has("customData")) {
            this.zzRJ = jSONObject.getJSONObject("customData");
            return true;
        }
        return z;
    }

    void zzlq() throws IllegalArgumentException {
        if (this.zzRS == null) {
            throw new IllegalArgumentException("media cannot be null.");
        }
        if (Double.isNaN(this.zzRV) || this.zzRV < 0.0d) {
            throw new IllegalArgumentException("startTime cannot be negative or NaN.");
        }
        if (Double.isNaN(this.zzRW)) {
            throw new IllegalArgumentException("playbackDuration cannot be NaN.");
        }
        if (Double.isNaN(this.zzRX) || this.zzRX < 0.0d) {
            throw new IllegalArgumentException("preloadTime cannot be negative or Nan.");
        }
    }

    public double zzlr() {
        return this.zzRW;
    }
}
