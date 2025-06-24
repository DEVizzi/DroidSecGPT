package com.google.android.gms.cast;

import android.support.v7.media.MediaRouteProviderProtocol;
import android.util.SparseArray;
import com.google.android.gms.cast.internal.zzf;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
/* loaded from: classes.dex */
public final class MediaStatus {
    public static final long COMMAND_PAUSE = 1;
    public static final long COMMAND_SEEK = 2;
    public static final long COMMAND_SET_VOLUME = 4;
    public static final long COMMAND_SKIP_BACKWARD = 32;
    public static final long COMMAND_SKIP_FORWARD = 16;
    public static final long COMMAND_TOGGLE_MUTE = 8;
    public static final int IDLE_REASON_CANCELED = 2;
    public static final int IDLE_REASON_ERROR = 4;
    public static final int IDLE_REASON_FINISHED = 1;
    public static final int IDLE_REASON_INTERRUPTED = 3;
    public static final int IDLE_REASON_NONE = 0;
    public static final int PLAYER_STATE_BUFFERING = 4;
    public static final int PLAYER_STATE_IDLE = 1;
    public static final int PLAYER_STATE_PAUSED = 3;
    public static final int PLAYER_STATE_PLAYING = 2;
    public static final int PLAYER_STATE_UNKNOWN = 0;
    public static final int REPEAT_MODE_REPEAT_ALL = 1;
    public static final int REPEAT_MODE_REPEAT_ALL_AND_SHUFFLE = 3;
    public static final int REPEAT_MODE_REPEAT_OFF = 0;
    public static final int REPEAT_MODE_REPEAT_SINGLE = 2;
    private JSONObject zzRJ;
    private MediaInfo zzRK;
    private long[] zzRY;
    private long zzSb;
    private double zzSc;
    private int zzSd;
    private int zzSe;
    private long zzSf;
    private long zzSg;
    private double zzSh;
    private boolean zzSi;
    private int zzSa = 0;
    private int zzSj = 0;
    private int zzSk = 0;
    private final zza zzSl = new zza();

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class zza {
        private int zzSm = 0;
        private List<MediaQueueItem> zzSn = new ArrayList();
        private SparseArray<Integer> zzSo = new SparseArray<>();

        zza() {
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clear() {
            this.zzSm = 0;
            this.zzSn.clear();
            this.zzSo.clear();
        }

        private void zza(MediaQueueItem[] mediaQueueItemArr) {
            this.zzSn.clear();
            this.zzSo.clear();
            for (int i = 0; i < mediaQueueItemArr.length; i++) {
                MediaQueueItem mediaQueueItem = mediaQueueItemArr[i];
                this.zzSn.add(mediaQueueItem);
                this.zzSo.put(mediaQueueItem.getItemId(), Integer.valueOf(i));
            }
        }

        private Integer zzaF(int i) {
            return this.zzSo.get(i);
        }

        /* JADX INFO: Access modifiers changed from: private */
        /* JADX WARN: Removed duplicated region for block: B:13:0x002f  */
        /* JADX WARN: Removed duplicated region for block: B:49:0x00f5  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public boolean zzg(org.json.JSONObject r11) throws org.json.JSONException {
            /*
                Method dump skipped, instructions count: 280
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.cast.MediaStatus.zza.zzg(org.json.JSONObject):boolean");
        }

        public int getItemCount() {
            return this.zzSn.size();
        }

        public int getRepeatMode() {
            return this.zzSm;
        }

        public MediaQueueItem zzaD(int i) {
            Integer num = this.zzSo.get(i);
            if (num == null) {
                return null;
            }
            return this.zzSn.get(num.intValue());
        }

        public MediaQueueItem zzaE(int i) {
            if (i < 0 || i >= this.zzSn.size()) {
                return null;
            }
            return this.zzSn.get(i);
        }

        public List<MediaQueueItem> zzlt() {
            return Collections.unmodifiableList(this.zzSn);
        }
    }

    public MediaStatus(JSONObject json) throws JSONException {
        zza(json, 0);
    }

    private boolean zzh(int i, int i2) {
        return i == 1 && i2 == 0;
    }

    public long[] getActiveTrackIds() {
        return this.zzRY;
    }

    public int getCurrentItemId() {
        return this.zzSa;
    }

    public JSONObject getCustomData() {
        return this.zzRJ;
    }

    public int getIdleReason() {
        return this.zzSe;
    }

    public int getLoadingItemId() {
        return this.zzSj;
    }

    public MediaInfo getMediaInfo() {
        return this.zzRK;
    }

    public double getPlaybackRate() {
        return this.zzSc;
    }

    public int getPlayerState() {
        return this.zzSd;
    }

    public int getPreloadedItemId() {
        return this.zzSk;
    }

    public MediaQueueItem getQueueItem(int index) {
        return this.zzSl.zzaE(index);
    }

    public MediaQueueItem getQueueItemById(int itemId) {
        return this.zzSl.zzaD(itemId);
    }

    public int getQueueItemCount() {
        return this.zzSl.getItemCount();
    }

    public List<MediaQueueItem> getQueueItems() {
        return this.zzSl.zzlt();
    }

    public int getQueueRepeatMode() {
        return this.zzSl.getRepeatMode();
    }

    public long getStreamPosition() {
        return this.zzSf;
    }

    public double getStreamVolume() {
        return this.zzSh;
    }

    public boolean isMediaCommandSupported(long mediaCommand) {
        return (this.zzSg & mediaCommand) != 0;
    }

    public boolean isMute() {
        return this.zzSi;
    }

    public int zza(JSONObject jSONObject, int i) throws JSONException {
        int i2;
        long[] jArr;
        boolean z;
        int i3;
        boolean z2 = true;
        long j = jSONObject.getLong("mediaSessionId");
        if (j != this.zzSb) {
            this.zzSb = j;
            i2 = 1;
        } else {
            i2 = 0;
        }
        if (jSONObject.has("playerState")) {
            String string = jSONObject.getString("playerState");
            int i4 = string.equals("IDLE") ? 1 : string.equals("PLAYING") ? 2 : string.equals("PAUSED") ? 3 : string.equals("BUFFERING") ? 4 : 0;
            if (i4 != this.zzSd) {
                this.zzSd = i4;
                i2 |= 2;
            }
            if (i4 == 1 && jSONObject.has("idleReason")) {
                String string2 = jSONObject.getString("idleReason");
                int i5 = string2.equals("CANCELLED") ? 2 : string2.equals("INTERRUPTED") ? 3 : string2.equals("FINISHED") ? 1 : string2.equals("ERROR") ? 4 : 0;
                if (i5 != this.zzSe) {
                    this.zzSe = i5;
                    i2 |= 2;
                }
            }
        }
        if (jSONObject.has("playbackRate")) {
            double d = jSONObject.getDouble("playbackRate");
            if (this.zzSc != d) {
                this.zzSc = d;
                i2 |= 2;
            }
        }
        if (jSONObject.has("currentTime") && (i & 2) == 0) {
            long zze = zzf.zze(jSONObject.getDouble("currentTime"));
            if (zze != this.zzSf) {
                this.zzSf = zze;
                i2 |= 2;
            }
        }
        if (jSONObject.has("supportedMediaCommands")) {
            long j2 = jSONObject.getLong("supportedMediaCommands");
            if (j2 != this.zzSg) {
                this.zzSg = j2;
                i2 |= 2;
            }
        }
        if (jSONObject.has(MediaRouteProviderProtocol.CLIENT_DATA_VOLUME) && (i & 1) == 0) {
            JSONObject jSONObject2 = jSONObject.getJSONObject(MediaRouteProviderProtocol.CLIENT_DATA_VOLUME);
            double d2 = jSONObject2.getDouble("level");
            if (d2 != this.zzSh) {
                this.zzSh = d2;
                i2 |= 2;
            }
            boolean z3 = jSONObject2.getBoolean("muted");
            if (z3 != this.zzSi) {
                this.zzSi = z3;
                i2 |= 2;
            }
        }
        if (jSONObject.has("activeTrackIds")) {
            JSONArray jSONArray = jSONObject.getJSONArray("activeTrackIds");
            int length = jSONArray.length();
            long[] jArr2 = new long[length];
            for (int i6 = 0; i6 < length; i6++) {
                jArr2[i6] = jSONArray.getLong(i6);
            }
            if (this.zzRY != null && this.zzRY.length == length) {
                int i7 = 0;
                while (true) {
                    if (i7 >= length) {
                        z2 = false;
                        break;
                    } else if (this.zzRY[i7] != jArr2[i7]) {
                        break;
                    } else {
                        i7++;
                    }
                }
            }
            if (z2) {
                this.zzRY = jArr2;
            }
            z = z2;
            jArr = jArr2;
        } else if (this.zzRY != null) {
            z = true;
            jArr = null;
        } else {
            jArr = null;
            z = false;
        }
        if (z) {
            this.zzRY = jArr;
            i2 |= 2;
        }
        if (jSONObject.has("customData")) {
            this.zzRJ = jSONObject.getJSONObject("customData");
            i2 |= 2;
        }
        if (jSONObject.has("media")) {
            JSONObject jSONObject3 = jSONObject.getJSONObject("media");
            this.zzRK = new MediaInfo(jSONObject3);
            i2 |= 2;
            if (jSONObject3.has("metadata")) {
                i2 |= 4;
            }
        }
        if (jSONObject.has("currentItemId") && this.zzSa != (i3 = jSONObject.getInt("currentItemId"))) {
            this.zzSa = i3;
            i2 |= 2;
        }
        int optInt = jSONObject.optInt("preloadedItemId", 0);
        if (this.zzSk != optInt) {
            this.zzSk = optInt;
            i2 |= 16;
        }
        int optInt2 = jSONObject.optInt("loadingItemId", 0);
        if (this.zzSj != optInt2) {
            this.zzSj = optInt2;
            i2 |= 2;
        }
        if (!zzh(this.zzSd, this.zzSj)) {
            return this.zzSl.zzg(jSONObject) ? i2 | 8 : i2;
        }
        this.zzSa = 0;
        this.zzSj = 0;
        this.zzSk = 0;
        if (this.zzSl.getItemCount() > 0) {
            this.zzSl.clear();
            return i2 | 8;
        }
        return i2;
    }

    public long zzls() {
        return this.zzSb;
    }
}
