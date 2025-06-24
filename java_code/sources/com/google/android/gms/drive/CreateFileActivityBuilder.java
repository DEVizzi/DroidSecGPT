package com.google.android.gms.drive;

import android.content.IntentSender;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.drive.internal.zzt;
/* loaded from: classes.dex */
public class CreateFileActivityBuilder {
    public static final String EXTRA_RESPONSE_DRIVE_ID = "response_drive_id";
    private final com.google.android.gms.drive.internal.zzj zzacV = new com.google.android.gms.drive.internal.zzj(0);
    private DriveContents zzacW;
    private boolean zzacX;

    public IntentSender build(GoogleApiClient apiClient) {
        zzu.zzb(Boolean.valueOf(this.zzacX), "Must call setInitialDriveContents to CreateFileActivityBuilder.");
        zzu.zza(apiClient.isConnected(), "Client must be connected");
        zzu.zzb(apiClient.zza(Drive.SCOPE_FILE) || apiClient.zza(Drive.zzacY), "The apiClient must have suitable scope to create files");
        if (this.zzacW != null) {
            this.zzacW.zzpf();
        }
        return this.zzacV.build(apiClient);
    }

    public CreateFileActivityBuilder setActivityStartFolder(DriveId folder) {
        this.zzacV.zza(folder);
        return this;
    }

    public CreateFileActivityBuilder setActivityTitle(String title) {
        this.zzacV.zzcv(title);
        return this;
    }

    public CreateFileActivityBuilder setInitialDriveContents(DriveContents driveContents) {
        if (driveContents == null) {
            this.zzacV.zzct(1);
        } else if (!(driveContents instanceof zzt)) {
            throw new IllegalArgumentException("Only DriveContents obtained from the Drive API are accepted.");
        } else {
            if (driveContents.getDriveId() != null) {
                throw new IllegalArgumentException("Only DriveContents obtained through DriveApi.newDriveContents are accepted for file creation.");
            }
            if (driveContents.zzpg()) {
                throw new IllegalArgumentException("DriveContents are already closed.");
            }
            this.zzacV.zzct(driveContents.zzpe().getRequestId());
            this.zzacW = driveContents;
        }
        this.zzacX = true;
        return this;
    }

    public CreateFileActivityBuilder setInitialMetadata(MetadataChangeSet metadataChangeSet) {
        this.zzacV.zza(metadataChangeSet);
        return this;
    }
}
