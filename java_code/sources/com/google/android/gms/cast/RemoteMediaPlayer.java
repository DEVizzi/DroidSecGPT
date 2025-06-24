package com.google.android.gms.cast;

import com.google.android.gms.cast.Cast;
import com.google.android.gms.cast.internal.zze;
import com.google.android.gms.cast.internal.zzm;
import com.google.android.gms.cast.internal.zzn;
import com.google.android.gms.cast.internal.zzo;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.ResultCallback;
import com.google.android.gms.common.api.Status;
import java.io.IOException;
import java.util.Locale;
import org.json.JSONObject;
/* loaded from: classes.dex */
public class RemoteMediaPlayer implements Cast.MessageReceivedCallback {
    public static final int RESUME_STATE_PAUSE = 2;
    public static final int RESUME_STATE_PLAY = 1;
    public static final int RESUME_STATE_UNCHANGED = 0;
    public static final int STATUS_CANCELED = 2101;
    public static final int STATUS_FAILED = 2100;
    public static final int STATUS_REPLACED = 2103;
    public static final int STATUS_SUCCEEDED = 0;
    public static final int STATUS_TIMED_OUT = 2102;
    private OnPreloadStatusUpdatedListener zzSv;
    private OnQueueStatusUpdatedListener zzSw;
    private OnMetadataUpdatedListener zzSx;
    private OnStatusUpdatedListener zzSy;
    private final Object zzqt = new Object();
    private final zza zzSu = new zza();
    private final zzm zzSt = new zzm(null) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.1
        @Override // com.google.android.gms.cast.internal.zzm
        protected void onMetadataUpdated() {
            RemoteMediaPlayer.this.onMetadataUpdated();
        }

        @Override // com.google.android.gms.cast.internal.zzm
        protected void onPreloadStatusUpdated() {
            RemoteMediaPlayer.this.onPreloadStatusUpdated();
        }

        @Override // com.google.android.gms.cast.internal.zzm
        protected void onQueueStatusUpdated() {
            RemoteMediaPlayer.this.onQueueStatusUpdated();
        }

        @Override // com.google.android.gms.cast.internal.zzm
        protected void onStatusUpdated() {
            RemoteMediaPlayer.this.onStatusUpdated();
        }
    };

    /* loaded from: classes.dex */
    public interface MediaChannelResult extends Result {
        JSONObject getCustomData();
    }

    /* loaded from: classes.dex */
    public interface OnMetadataUpdatedListener {
        void onMetadataUpdated();
    }

    /* loaded from: classes.dex */
    public interface OnPreloadStatusUpdatedListener {
        void onPreloadStatusUpdated();
    }

    /* loaded from: classes.dex */
    public interface OnQueueStatusUpdatedListener {
        void onQueueStatusUpdated();
    }

    /* loaded from: classes.dex */
    public interface OnStatusUpdatedListener {
        void onStatusUpdated();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class zza implements zzn {
        private GoogleApiClient zzSW;
        private long zzSX = 0;

        /* renamed from: com.google.android.gms.cast.RemoteMediaPlayer$zza$zza  reason: collision with other inner class name */
        /* loaded from: classes.dex */
        private final class C0030zza implements ResultCallback<Status> {
            private final long zzSY;

            C0030zza(long j) {
                this.zzSY = j;
            }

            @Override // com.google.android.gms.common.api.ResultCallback
            /* renamed from: zzm */
            public void onResult(Status status) {
                if (status.isSuccess()) {
                    return;
                }
                RemoteMediaPlayer.this.zzSt.zzb(this.zzSY, status.getStatusCode());
            }
        }

        public zza() {
        }

        @Override // com.google.android.gms.cast.internal.zzn
        public void zza(String str, String str2, long j, String str3) throws IOException {
            if (this.zzSW == null) {
                throw new IOException("No GoogleApiClient available");
            }
            Cast.CastApi.sendMessage(this.zzSW, str, str2).setResultCallback(new C0030zza(j));
        }

        public void zzb(GoogleApiClient googleApiClient) {
            this.zzSW = googleApiClient;
        }

        @Override // com.google.android.gms.cast.internal.zzn
        public long zzlu() {
            long j = this.zzSX + 1;
            this.zzSX = j;
            return j;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static abstract class zzb extends com.google.android.gms.cast.internal.zzb<MediaChannelResult> {
        zzo zzTa;

        zzb(GoogleApiClient googleApiClient) {
            super(googleApiClient);
            this.zzTa = new zzo() { // from class: com.google.android.gms.cast.RemoteMediaPlayer.zzb.1
                @Override // com.google.android.gms.cast.internal.zzo
                public void zza(long j, int i, Object obj) {
                    zzb.this.setResult(new zzc(new Status(i), obj instanceof JSONObject ? (JSONObject) obj : null));
                }

                @Override // com.google.android.gms.cast.internal.zzo
                public void zzy(long j) {
                    zzb.this.setResult(zzb.this.createFailedResult(new Status(2103)));
                }
            };
        }

        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzn */
        public MediaChannelResult createFailedResult(final Status status) {
            return new MediaChannelResult() { // from class: com.google.android.gms.cast.RemoteMediaPlayer.zzb.2
                @Override // com.google.android.gms.cast.RemoteMediaPlayer.MediaChannelResult
                public JSONObject getCustomData() {
                    return null;
                }

                @Override // com.google.android.gms.common.api.Result
                public Status getStatus() {
                    return status;
                }
            };
        }
    }

    /* loaded from: classes.dex */
    private static final class zzc implements MediaChannelResult {
        private final Status zzOt;
        private final JSONObject zzRJ;

        zzc(Status status, JSONObject jSONObject) {
            this.zzOt = status;
            this.zzRJ = jSONObject;
        }

        @Override // com.google.android.gms.cast.RemoteMediaPlayer.MediaChannelResult
        public JSONObject getCustomData() {
            return this.zzRJ;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }
    }

    public RemoteMediaPlayer() {
        this.zzSt.zza(this.zzSu);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onMetadataUpdated() {
        if (this.zzSx != null) {
            this.zzSx.onMetadataUpdated();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onPreloadStatusUpdated() {
        if (this.zzSv != null) {
            this.zzSv.onPreloadStatusUpdated();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onQueueStatusUpdated() {
        if (this.zzSw != null) {
            this.zzSw.onQueueStatusUpdated();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onStatusUpdated() {
        if (this.zzSy != null) {
            this.zzSy.onStatusUpdated();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int zzaH(int i) {
        MediaStatus mediaStatus = getMediaStatus();
        for (int i2 = 0; i2 < mediaStatus.getQueueItemCount(); i2++) {
            if (mediaStatus.getQueueItem(i2).getItemId() == i) {
                return i2;
            }
        }
        return -1;
    }

    public long getApproximateStreamPosition() {
        long approximateStreamPosition;
        synchronized (this.zzqt) {
            approximateStreamPosition = this.zzSt.getApproximateStreamPosition();
        }
        return approximateStreamPosition;
    }

    public MediaInfo getMediaInfo() {
        MediaInfo mediaInfo;
        synchronized (this.zzqt) {
            mediaInfo = this.zzSt.getMediaInfo();
        }
        return mediaInfo;
    }

    public MediaStatus getMediaStatus() {
        MediaStatus mediaStatus;
        synchronized (this.zzqt) {
            mediaStatus = this.zzSt.getMediaStatus();
        }
        return mediaStatus;
    }

    public String getNamespace() {
        return this.zzSt.getNamespace();
    }

    public long getStreamDuration() {
        long streamDuration;
        synchronized (this.zzqt) {
            streamDuration = this.zzSt.getStreamDuration();
        }
        return streamDuration;
    }

    public PendingResult<MediaChannelResult> load(GoogleApiClient apiClient, MediaInfo mediaInfo) {
        return load(apiClient, mediaInfo, true, 0L, null, null);
    }

    public PendingResult<MediaChannelResult> load(GoogleApiClient apiClient, MediaInfo mediaInfo, boolean autoplay) {
        return load(apiClient, mediaInfo, autoplay, 0L, null, null);
    }

    public PendingResult<MediaChannelResult> load(GoogleApiClient apiClient, MediaInfo mediaInfo, boolean autoplay, long playPosition) {
        return load(apiClient, mediaInfo, autoplay, playPosition, null, null);
    }

    public PendingResult<MediaChannelResult> load(GoogleApiClient apiClient, MediaInfo mediaInfo, boolean autoplay, long playPosition, JSONObject customData) {
        return load(apiClient, mediaInfo, autoplay, playPosition, null, customData);
    }

    public PendingResult<MediaChannelResult> load(final GoogleApiClient apiClient, final MediaInfo mediaInfo, final boolean autoplay, final long playPosition, final long[] activeTrackIds, final JSONObject customData) {
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.12
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zza(this.zzTa, mediaInfo, autoplay, playPosition, activeTrackIds, customData);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    @Override // com.google.android.gms.cast.Cast.MessageReceivedCallback
    public void onMessageReceived(CastDevice castDevice, String namespace, String message) {
        this.zzSt.zzbB(message);
    }

    public PendingResult<MediaChannelResult> pause(GoogleApiClient apiClient) {
        return pause(apiClient, null);
    }

    public PendingResult<MediaChannelResult> pause(final GoogleApiClient apiClient, final JSONObject customData) {
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.16
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zza(this.zzTa, customData);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    public PendingResult<MediaChannelResult> play(GoogleApiClient apiClient) {
        return play(apiClient, null);
    }

    public PendingResult<MediaChannelResult> play(final GoogleApiClient apiClient, final JSONObject customData) {
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.18
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zzc(this.zzTa, customData);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    public PendingResult<MediaChannelResult> queueAppendItem(GoogleApiClient apiClient, MediaQueueItem item, JSONObject customData) throws IllegalArgumentException {
        return queueInsertItems(apiClient, new MediaQueueItem[]{item}, 0, customData);
    }

    public PendingResult<MediaChannelResult> queueInsertItems(final GoogleApiClient apiClient, final MediaQueueItem[] itemsToInsert, final int insertBeforeItemId, final JSONObject customData) throws IllegalArgumentException {
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.5
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zza(this.zzTa, itemsToInsert, insertBeforeItemId, customData);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    public PendingResult<MediaChannelResult> queueJumpToItem(final GoogleApiClient apiClient, final int itemId, final JSONObject customData) {
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.14
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    if (RemoteMediaPlayer.this.zzaH(itemId) == -1) {
                        setResult(createFailedResult(new Status(0)));
                        return;
                    }
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zza(this.zzTa, itemId, (MediaQueueItem[]) null, 0, (Integer) null, customData);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    public PendingResult<MediaChannelResult> queueLoad(final GoogleApiClient apiClient, final MediaQueueItem[] items, final int startIndex, final int repeatMode, final JSONObject customData) throws IllegalArgumentException {
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.4
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zza(this.zzTa, items, startIndex, repeatMode, customData);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    public PendingResult<MediaChannelResult> queueMoveItemToNewIndex(final GoogleApiClient apiClient, final int itemId, final int newIndex, final JSONObject customData) {
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.15
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    int zzaH = RemoteMediaPlayer.this.zzaH(itemId);
                    if (zzaH == -1) {
                        setResult(createFailedResult(new Status(0)));
                    } else if (newIndex < 0) {
                        setResult(createFailedResult(new Status(2001, String.format(Locale.ROOT, "Invalid request: Invalid newIndex %d.", Integer.valueOf(newIndex)))));
                    } else if (zzaH == newIndex) {
                        setResult(createFailedResult(new Status(0)));
                    } else {
                        MediaQueueItem queueItem = RemoteMediaPlayer.this.getMediaStatus().getQueueItem(newIndex > zzaH ? newIndex + 1 : newIndex);
                        int itemId2 = queueItem != null ? queueItem.getItemId() : 0;
                        RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                        try {
                            RemoteMediaPlayer.this.zzSt.zza(this.zzTa, new int[]{itemId}, itemId2, customData);
                            RemoteMediaPlayer.this.zzSu.zzb(null);
                        } catch (IOException e) {
                            setResult(createFailedResult(new Status(2100)));
                            RemoteMediaPlayer.this.zzSu.zzb(null);
                        }
                    }
                }
            }
        });
    }

    public PendingResult<MediaChannelResult> queueNext(final GoogleApiClient apiClient, final JSONObject customData) {
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.10
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zza(this.zzTa, 0, (MediaQueueItem[]) null, 1, (Integer) null, customData);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    public PendingResult<MediaChannelResult> queuePrev(final GoogleApiClient apiClient, final JSONObject customData) {
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.9
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zza(this.zzTa, 0, (MediaQueueItem[]) null, -1, (Integer) null, customData);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    public PendingResult<MediaChannelResult> queueRemoveItem(final GoogleApiClient apiClient, final int itemId, final JSONObject customData) {
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.13
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    if (RemoteMediaPlayer.this.zzaH(itemId) == -1) {
                        setResult(createFailedResult(new Status(0)));
                        return;
                    }
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zza(this.zzTa, new int[]{itemId}, customData);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    public PendingResult<MediaChannelResult> queueRemoveItems(final GoogleApiClient apiClient, final int[] itemIdsToRemove, final JSONObject customData) throws IllegalArgumentException {
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.7
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zza(this.zzTa, itemIdsToRemove, customData);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    public PendingResult<MediaChannelResult> queueReorderItems(final GoogleApiClient apiClient, final int[] itemIdsToReorder, final int insertBeforeItemId, final JSONObject customData) throws IllegalArgumentException {
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.8
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zza(this.zzTa, itemIdsToReorder, insertBeforeItemId, customData);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    public PendingResult<MediaChannelResult> queueSetRepeatMode(final GoogleApiClient apiClient, final int repeatMode, final JSONObject customData) {
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.11
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zza(this.zzTa, 0, (MediaQueueItem[]) null, 0, Integer.valueOf(repeatMode), customData);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    public PendingResult<MediaChannelResult> queueUpdateItems(final GoogleApiClient apiClient, final MediaQueueItem[] itemsToUpdate, final JSONObject customData) {
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.6
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zza(this.zzTa, 0, itemsToUpdate, 0, (Integer) null, customData);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    public PendingResult<MediaChannelResult> requestStatus(final GoogleApiClient apiClient) {
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.22
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zza(this.zzTa);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    public PendingResult<MediaChannelResult> seek(GoogleApiClient apiClient, long position) {
        return seek(apiClient, position, 0, null);
    }

    public PendingResult<MediaChannelResult> seek(GoogleApiClient apiClient, long position, int resumeState) {
        return seek(apiClient, position, resumeState, null);
    }

    public PendingResult<MediaChannelResult> seek(final GoogleApiClient apiClient, final long position, final int resumeState, final JSONObject customData) {
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.19
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zza(this.zzTa, position, resumeState, customData);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    public PendingResult<MediaChannelResult> setActiveMediaTracks(final GoogleApiClient apiClient, final long[] trackIds) {
        if (trackIds == null) {
            throw new IllegalArgumentException("trackIds cannot be null");
        }
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zza(this.zzTa, trackIds);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    public void setOnMetadataUpdatedListener(OnMetadataUpdatedListener listener) {
        this.zzSx = listener;
    }

    public void setOnPreloadStatusUpdatedListener(OnPreloadStatusUpdatedListener listener) {
        this.zzSv = listener;
    }

    public void setOnQueueStatusUpdatedListener(OnQueueStatusUpdatedListener listener) {
        this.zzSw = listener;
    }

    public void setOnStatusUpdatedListener(OnStatusUpdatedListener listener) {
        this.zzSy = listener;
    }

    public PendingResult<MediaChannelResult> setStreamMute(GoogleApiClient apiClient, boolean muteState) {
        return setStreamMute(apiClient, muteState, null);
    }

    public PendingResult<MediaChannelResult> setStreamMute(final GoogleApiClient apiClient, final boolean muteState, final JSONObject customData) {
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.21
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zza(this.zzTa, muteState, customData);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException | IllegalStateException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    public PendingResult<MediaChannelResult> setStreamVolume(GoogleApiClient apiClient, double volume) throws IllegalArgumentException {
        return setStreamVolume(apiClient, volume, null);
    }

    public PendingResult<MediaChannelResult> setStreamVolume(final GoogleApiClient apiClient, final double volume, final JSONObject customData) throws IllegalArgumentException {
        if (Double.isInfinite(volume) || Double.isNaN(volume)) {
            throw new IllegalArgumentException("Volume cannot be " + volume);
        }
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.20
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zza(this.zzTa, volume, customData);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException | IllegalArgumentException | IllegalStateException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    public PendingResult<MediaChannelResult> setTextTrackStyle(final GoogleApiClient apiClient, final TextTrackStyle trackStyle) {
        if (trackStyle == null) {
            throw new IllegalArgumentException("trackStyle cannot be null");
        }
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.3
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zza(this.zzTa, trackStyle);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }

    public PendingResult<MediaChannelResult> stop(GoogleApiClient apiClient) {
        return stop(apiClient, null);
    }

    public PendingResult<MediaChannelResult> stop(final GoogleApiClient apiClient, final JSONObject customData) {
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.cast.RemoteMediaPlayer.17
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zze zzeVar) {
                synchronized (RemoteMediaPlayer.this.zzqt) {
                    RemoteMediaPlayer.this.zzSu.zzb(apiClient);
                    try {
                        RemoteMediaPlayer.this.zzSt.zzb(this.zzTa, customData);
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    } catch (IOException e) {
                        setResult(createFailedResult(new Status(2100)));
                        RemoteMediaPlayer.this.zzSu.zzb(null);
                    }
                }
            }
        });
    }
}
