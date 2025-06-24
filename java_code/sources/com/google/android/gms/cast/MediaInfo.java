package com.google.android.gms.cast;

import android.text.TextUtils;
import com.google.android.gms.cast.internal.zzf;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.internal.zzlh;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
/* loaded from: classes.dex */
public final class MediaInfo {
    public static final int STREAM_TYPE_BUFFERED = 1;
    public static final int STREAM_TYPE_INVALID = -1;
    public static final int STREAM_TYPE_LIVE = 2;
    public static final int STREAM_TYPE_NONE = 0;
    public static final long UNKNOWN_DURATION = -1;
    private final String zzRC;
    private int zzRD;
    private String zzRE;
    private MediaMetadata zzRF;
    private long zzRG;
    private List<MediaTrack> zzRH;
    private TextTrackStyle zzRI;
    private JSONObject zzRJ;

    /* loaded from: classes.dex */
    public static class Builder {
        private final MediaInfo zzRK;

        public Builder(String contentId) throws IllegalArgumentException {
            if (TextUtils.isEmpty(contentId)) {
                throw new IllegalArgumentException("Content ID cannot be empty");
            }
            this.zzRK = new MediaInfo(contentId);
        }

        public MediaInfo build() throws IllegalArgumentException {
            this.zzRK.zzlq();
            return this.zzRK;
        }

        public Builder setContentType(String contentType) throws IllegalArgumentException {
            this.zzRK.setContentType(contentType);
            return this;
        }

        public Builder setCustomData(JSONObject customData) {
            this.zzRK.setCustomData(customData);
            return this;
        }

        public Builder setMediaTracks(List<MediaTrack> mediaTracks) {
            this.zzRK.zzj(mediaTracks);
            return this;
        }

        public Builder setMetadata(MediaMetadata metadata) {
            this.zzRK.zza(metadata);
            return this;
        }

        public Builder setStreamDuration(long duration) throws IllegalArgumentException {
            this.zzRK.zzx(duration);
            return this;
        }

        public Builder setStreamType(int streamType) throws IllegalArgumentException {
            this.zzRK.setStreamType(streamType);
            return this;
        }

        public Builder setTextTrackStyle(TextTrackStyle textTrackStyle) {
            this.zzRK.setTextTrackStyle(textTrackStyle);
            return this;
        }
    }

    MediaInfo(String contentId) throws IllegalArgumentException {
        if (TextUtils.isEmpty(contentId)) {
            throw new IllegalArgumentException("content ID cannot be null or empty");
        }
        this.zzRC = contentId;
        this.zzRD = -1;
        this.zzRG = -1L;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MediaInfo(JSONObject json) throws JSONException {
        this.zzRC = json.getString("contentId");
        String string = json.getString("streamType");
        if ("NONE".equals(string)) {
            this.zzRD = 0;
        } else if ("BUFFERED".equals(string)) {
            this.zzRD = 1;
        } else if ("LIVE".equals(string)) {
            this.zzRD = 2;
        } else {
            this.zzRD = -1;
        }
        this.zzRE = json.getString("contentType");
        if (json.has("metadata")) {
            JSONObject jSONObject = json.getJSONObject("metadata");
            this.zzRF = new MediaMetadata(jSONObject.getInt("metadataType"));
            this.zzRF.zzf(jSONObject);
        }
        this.zzRG = -1L;
        if (json.has("duration") && !json.isNull("duration")) {
            double optDouble = json.optDouble("duration", 0.0d);
            if (!Double.isNaN(optDouble) && !Double.isInfinite(optDouble)) {
                this.zzRG = zzf.zze(optDouble);
            }
        }
        if (json.has("tracks")) {
            this.zzRH = new ArrayList();
            JSONArray jSONArray = json.getJSONArray("tracks");
            for (int i = 0; i < jSONArray.length(); i++) {
                this.zzRH.add(new MediaTrack(jSONArray.getJSONObject(i)));
            }
        } else {
            this.zzRH = null;
        }
        if (json.has("textTrackStyle")) {
            JSONObject jSONObject2 = json.getJSONObject("textTrackStyle");
            TextTrackStyle textTrackStyle = new TextTrackStyle();
            textTrackStyle.zzf(jSONObject2);
            this.zzRI = textTrackStyle;
        } else {
            this.zzRI = null;
        }
        this.zzRJ = json.optJSONObject("customData");
    }

    public boolean equals(Object other) {
        boolean z = true;
        if (this == other) {
            return true;
        }
        if (other instanceof MediaInfo) {
            MediaInfo mediaInfo = (MediaInfo) other;
            if ((this.zzRJ == null) == (mediaInfo.zzRJ == null)) {
                if (this.zzRJ == null || mediaInfo.zzRJ == null || zzlh.zzd(this.zzRJ, mediaInfo.zzRJ)) {
                    if (!zzf.zza(this.zzRC, mediaInfo.zzRC) || this.zzRD != mediaInfo.zzRD || !zzf.zza(this.zzRE, mediaInfo.zzRE) || !zzf.zza(this.zzRF, mediaInfo.zzRF) || this.zzRG != mediaInfo.zzRG) {
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

    public String getContentId() {
        return this.zzRC;
    }

    public String getContentType() {
        return this.zzRE;
    }

    public JSONObject getCustomData() {
        return this.zzRJ;
    }

    public List<MediaTrack> getMediaTracks() {
        return this.zzRH;
    }

    public MediaMetadata getMetadata() {
        return this.zzRF;
    }

    public long getStreamDuration() {
        return this.zzRG;
    }

    public int getStreamType() {
        return this.zzRD;
    }

    public TextTrackStyle getTextTrackStyle() {
        return this.zzRI;
    }

    public int hashCode() {
        return zzt.hashCode(this.zzRC, Integer.valueOf(this.zzRD), this.zzRE, this.zzRF, Long.valueOf(this.zzRG), String.valueOf(this.zzRJ));
    }

    void setContentType(String contentType) throws IllegalArgumentException {
        if (TextUtils.isEmpty(contentType)) {
            throw new IllegalArgumentException("content type cannot be null or empty");
        }
        this.zzRE = contentType;
    }

    void setCustomData(JSONObject customData) {
        this.zzRJ = customData;
    }

    void setStreamType(int streamType) throws IllegalArgumentException {
        if (streamType < -1 || streamType > 2) {
            throw new IllegalArgumentException("invalid stream type");
        }
        this.zzRD = streamType;
    }

    public void setTextTrackStyle(TextTrackStyle textTrackStyle) {
        this.zzRI = textTrackStyle;
    }

    public JSONObject toJson() {
        String str;
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("contentId", this.zzRC);
            switch (this.zzRD) {
                case 1:
                    str = "BUFFERED";
                    break;
                case 2:
                    str = "LIVE";
                    break;
                default:
                    str = "NONE";
                    break;
            }
            jSONObject.put("streamType", str);
            if (this.zzRE != null) {
                jSONObject.put("contentType", this.zzRE);
            }
            if (this.zzRF != null) {
                jSONObject.put("metadata", this.zzRF.toJson());
            }
            if (this.zzRG <= -1) {
                jSONObject.put("duration", JSONObject.NULL);
            } else {
                jSONObject.put("duration", zzf.zzA(this.zzRG));
            }
            if (this.zzRH != null) {
                JSONArray jSONArray = new JSONArray();
                for (MediaTrack mediaTrack : this.zzRH) {
                    jSONArray.put(mediaTrack.toJson());
                }
                jSONObject.put("tracks", jSONArray);
            }
            if (this.zzRI != null) {
                jSONObject.put("textTrackStyle", this.zzRI.toJson());
            }
            if (this.zzRJ != null) {
                jSONObject.put("customData", this.zzRJ);
            }
        } catch (JSONException e) {
        }
        return jSONObject;
    }

    void zza(MediaMetadata mediaMetadata) {
        this.zzRF = mediaMetadata;
    }

    void zzj(List<MediaTrack> list) {
        this.zzRH = list;
    }

    void zzlq() throws IllegalArgumentException {
        if (TextUtils.isEmpty(this.zzRC)) {
            throw new IllegalArgumentException("content ID cannot be null or empty");
        }
        if (TextUtils.isEmpty(this.zzRE)) {
            throw new IllegalArgumentException("content type cannot be null or empty");
        }
        if (this.zzRD == -1) {
            throw new IllegalArgumentException("a valid stream type must be specified");
        }
    }

    void zzx(long j) throws IllegalArgumentException {
        if (j < 0 && j != -1) {
            throw new IllegalArgumentException("Invalid stream duration");
        }
        this.zzRG = j;
    }
}
