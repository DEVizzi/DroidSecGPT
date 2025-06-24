package com.google.android.gms.drive;

import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.drive.DriveApi;
import com.google.android.gms.drive.query.Query;
/* loaded from: classes.dex */
public interface DriveFolder extends DriveResource {
    public static final String MIME_TYPE = "application/vnd.google-apps.folder";

    /* loaded from: classes.dex */
    public interface DriveFileResult extends Result {
        DriveFile getDriveFile();
    }

    /* loaded from: classes.dex */
    public interface DriveFolderResult extends Result {
        DriveFolder getDriveFolder();
    }

    PendingResult<DriveFileResult> createFile(GoogleApiClient googleApiClient, MetadataChangeSet metadataChangeSet, DriveContents driveContents);

    PendingResult<DriveFileResult> createFile(GoogleApiClient googleApiClient, MetadataChangeSet metadataChangeSet, DriveContents driveContents, ExecutionOptions executionOptions);

    PendingResult<DriveFolderResult> createFolder(GoogleApiClient googleApiClient, MetadataChangeSet metadataChangeSet);

    PendingResult<DriveApi.MetadataBufferResult> listChildren(GoogleApiClient googleApiClient);

    PendingResult<DriveApi.MetadataBufferResult> queryChildren(GoogleApiClient googleApiClient, Query query);
}
