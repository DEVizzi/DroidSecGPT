package com.google.android.gms.games.snapshot;

import android.graphics.Bitmap;
import android.net.Uri;
import com.google.android.gms.common.data.BitmapTeleporter;
/* loaded from: classes.dex */
public abstract class SnapshotMetadataChange {
    public static final SnapshotMetadataChange EMPTY_CHANGE = new SnapshotMetadataChangeEntity();

    /* loaded from: classes.dex */
    public static final class Builder {
        private String zzakM;
        private Long zzavm;
        private Long zzavn;
        private BitmapTeleporter zzavo;
        private Uri zzavp;

        public SnapshotMetadataChange build() {
            return new SnapshotMetadataChangeEntity(this.zzakM, this.zzavm, this.zzavo, this.zzavp, this.zzavn);
        }

        public Builder fromMetadata(SnapshotMetadata metadata) {
            this.zzakM = metadata.getDescription();
            this.zzavm = Long.valueOf(metadata.getPlayedTime());
            this.zzavn = Long.valueOf(metadata.getProgressValue());
            if (this.zzavm.longValue() == -1) {
                this.zzavm = null;
            }
            this.zzavp = metadata.getCoverImageUri();
            if (this.zzavp != null) {
                this.zzavo = null;
            }
            return this;
        }

        public Builder setCoverImage(Bitmap coverImage) {
            this.zzavo = new BitmapTeleporter(coverImage);
            this.zzavp = null;
            return this;
        }

        public Builder setDescription(String description) {
            this.zzakM = description;
            return this;
        }

        public Builder setPlayedTimeMillis(long playedTimeMillis) {
            this.zzavm = Long.valueOf(playedTimeMillis);
            return this;
        }

        public Builder setProgressValue(long progressValue) {
            this.zzavn = Long.valueOf(progressValue);
            return this;
        }
    }

    public abstract Bitmap getCoverImage();

    public abstract String getDescription();

    public abstract Long getPlayedTimeMillis();

    public abstract Long getProgressValue();

    public abstract BitmapTeleporter zztQ();
}
