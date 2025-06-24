package com.google.android.gms.cast;

import android.text.TextUtils;
import com.google.android.gms.cast.internal.zzf;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.internal.zzlh;
import java.util.Locale;
import org.json.JSONException;
import org.json.JSONObject;
/* loaded from: classes.dex */
public final class MediaTrack {
    public static final int SUBTYPE_CAPTIONS = 2;
    public static final int SUBTYPE_CHAPTERS = 4;
    public static final int SUBTYPE_DESCRIPTIONS = 3;
    public static final int SUBTYPE_METADATA = 5;
    public static final int SUBTYPE_NONE = 0;
    public static final int SUBTYPE_SUBTITLES = 1;
    public static final int SUBTYPE_UNKNOWN = -1;
    public static final int TYPE_AUDIO = 2;
    public static final int TYPE_TEXT = 1;
    public static final int TYPE_UNKNOWN = 0;
    public static final int TYPE_VIDEO = 3;
    private String mName;
    private long zzOw;
    private String zzRA;
    private String zzRC;
    private String zzRE;
    private JSONObject zzRJ;
    private int zzSq;
    private int zzSr;

    /* loaded from: classes.dex */
    public static class Builder {
        private final MediaTrack zzSs;

        public Builder(long trackId, int trackType) throws IllegalArgumentException {
            this.zzSs = new MediaTrack(trackId, trackType);
        }

        public MediaTrack build() {
            return this.zzSs;
        }

        public Builder setContentId(String contentId) {
            this.zzSs.setContentId(contentId);
            return this;
        }

        public Builder setContentType(String contentType) {
            this.zzSs.setContentType(contentType);
            return this;
        }

        public Builder setCustomData(JSONObject customData) {
            this.zzSs.setCustomData(customData);
            return this;
        }

        public Builder setLanguage(String language) {
            this.zzSs.setLanguage(language);
            return this;
        }

        public Builder setLanguage(Locale locale) {
            this.zzSs.setLanguage(zzf.zzb(locale));
            return this;
        }

        public Builder setName(String trackName) {
            this.zzSs.setName(trackName);
            return this;
        }

        public Builder setSubtype(int subtype) throws IllegalArgumentException {
            this.zzSs.zzaG(subtype);
            return this;
        }
    }

    MediaTrack(long id, int type) throws IllegalArgumentException {
        clear();
        this.zzOw = id;
        if (type <= 0 || type > 3) {
            throw new IllegalArgumentException("invalid type " + type);
        }
        this.zzSq = type;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MediaTrack(JSONObject json) throws JSONException {
        zzf(json);
    }

    private void clear() {
        this.zzOw = 0L;
        this.zzSq = 0;
        this.zzRC = null;
        this.mName = null;
        this.zzRA = null;
        this.zzSr = -1;
        this.zzRJ = null;
    }

    private void zzf(JSONObject jSONObject) throws JSONException {
        clear();
        this.zzOw = jSONObject.getLong("trackId");
        String string = jSONObject.getString("type");
        if ("TEXT".equals(string)) {
            this.zzSq = 1;
        } else if ("AUDIO".equals(string)) {
            this.zzSq = 2;
        } else if (!"VIDEO".equals(string)) {
            throw new JSONException("invalid type: " + string);
        } else {
            this.zzSq = 3;
        }
        this.zzRC = jSONObject.optString("trackContentId", null);
        this.zzRE = jSONObject.optString("trackContentType", null);
        this.mName = jSONObject.optString("name", null);
        this.zzRA = jSONObject.optString("language", null);
        if (jSONObject.has("subtype")) {
            String string2 = jSONObject.getString("subtype");
            if ("SUBTITLES".equals(string2)) {
                this.zzSr = 1;
            } else if ("CAPTIONS".equals(string2)) {
                this.zzSr = 2;
            } else if ("DESCRIPTIONS".equals(string2)) {
                this.zzSr = 3;
            } else if ("CHAPTERS".equals(string2)) {
                this.zzSr = 4;
            } else if (!"METADATA".equals(string2)) {
                throw new JSONException("invalid subtype: " + string2);
            } else {
                this.zzSr = 5;
            }
        } else {
            this.zzSr = 0;
        }
        this.zzRJ = jSONObject.optJSONObject("customData");
    }

    public boolean equals(Object other) {
        boolean z = true;
        if (this == other) {
            return true;
        }
        if (other instanceof MediaTrack) {
            MediaTrack mediaTrack = (MediaTrack) other;
            if ((this.zzRJ == null) == (mediaTrack.zzRJ == null)) {
                if (this.zzRJ == null || mediaTrack.zzRJ == null || zzlh.zzd(this.zzRJ, mediaTrack.zzRJ)) {
                    if (this.zzOw != mediaTrack.zzOw || this.zzSq != mediaTrack.zzSq || !zzf.zza(this.zzRC, mediaTrack.zzRC) || !zzf.zza(this.zzRE, mediaTrack.zzRE) || !zzf.zza(this.mName, mediaTrack.mName) || !zzf.zza(this.zzRA, mediaTrack.zzRA) || this.zzSr != mediaTrack.zzSr) {
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

    public long getId() {
        return this.zzOw;
    }

    public String getLanguage() {
        return this.zzRA;
    }

    public String getName() {
        return this.mName;
    }

    public int getSubtype() {
        return this.zzSr;
    }

    public int getType() {
        return this.zzSq;
    }

    public int hashCode() {
        return zzt.hashCode(Long.valueOf(this.zzOw), Integer.valueOf(this.zzSq), this.zzRC, this.zzRE, this.mName, this.zzRA, Integer.valueOf(this.zzSr), this.zzRJ);
    }

    public void setContentId(String contentId) {
        this.zzRC = contentId;
    }

    public void setContentType(String contentType) {
        this.zzRE = contentType;
    }

    void setCustomData(JSONObject customData) {
        this.zzRJ = customData;
    }

    void setLanguage(String language) {
        this.zzRA = language;
    }

    void setName(String name) {
        this.mName = name;
    }

    public JSONObject toJson() {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("trackId", this.zzOw);
            switch (this.zzSq) {
                case 1:
                    jSONObject.put("type", "TEXT");
                    break;
                case 2:
                    jSONObject.put("type", "AUDIO");
                    break;
                case 3:
                    jSONObject.put("type", "VIDEO");
                    break;
            }
            if (this.zzRC != null) {
                jSONObject.put("trackContentId", this.zzRC);
            }
            if (this.zzRE != null) {
                jSONObject.put("trackContentType", this.zzRE);
            }
            if (this.mName != null) {
                jSONObject.put("name", this.mName);
            }
            if (!TextUtils.isEmpty(this.zzRA)) {
                jSONObject.put("language", this.zzRA);
            }
            switch (this.zzSr) {
                case 1:
                    jSONObject.put("subtype", "SUBTITLES");
                    break;
                case 2:
                    jSONObject.put("subtype", "CAPTIONS");
                    break;
                case 3:
                    jSONObject.put("subtype", "DESCRIPTIONS");
                    break;
                case 4:
                    jSONObject.put("subtype", "CHAPTERS");
                    break;
                case 5:
                    jSONObject.put("subtype", "METADATA");
                    break;
            }
            if (this.zzRJ != null) {
                jSONObject.put("customData", this.zzRJ);
            }
        } catch (JSONException e) {
        }
        return jSONObject;
    }

    void zzaG(int i) throws IllegalArgumentException {
        if (i <= -1 || i > 5) {
            throw new IllegalArgumentException("invalid subtype " + i);
        }
        if (i != 0 && this.zzSq != 1) {
            throw new IllegalArgumentException("subtypes are only valid for text tracks");
        }
        this.zzSr = i;
    }
}
