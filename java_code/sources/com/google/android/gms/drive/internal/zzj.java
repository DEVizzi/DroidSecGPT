package com.google.android.gms.drive.internal;

import android.content.IntentSender;
import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.drive.Drive;
import com.google.android.gms.drive.DriveId;
import com.google.android.gms.drive.MetadataChangeSet;
/* loaded from: classes.dex */
public class zzj {
    private String zzadv;
    private DriveId zzady;
    protected MetadataChangeSet zzaex;
    private Integer zzaey;
    private final int zzaez;

    public zzj(int i) {
        this.zzaez = i;
    }

    public IntentSender build(GoogleApiClient apiClient) {
        com.google.android.gms.common.internal.zzu.zzb(this.zzaex, "Must provide initial metadata to CreateFileActivityBuilder.");
        com.google.android.gms.common.internal.zzu.zza(apiClient.isConnected(), "Client must be connected");
        zzs zzsVar = (zzs) apiClient.zza(Drive.zzNX);
        this.zzaex.zzpm().setContext(zzsVar.getContext());
        try {
            return zzsVar.zzpB().zza(new CreateFileIntentSenderRequest(this.zzaex.zzpm(), this.zzaey == null ? 0 : this.zzaey.intValue(), this.zzadv, this.zzady, this.zzaez));
        } catch (RemoteException e) {
            throw new RuntimeException("Unable to connect Drive Play Service", e);
        }
    }

    public void zza(DriveId driveId) {
        this.zzady = (DriveId) com.google.android.gms.common.internal.zzu.zzu(driveId);
    }

    public void zza(MetadataChangeSet metadataChangeSet) {
        this.zzaex = (MetadataChangeSet) com.google.android.gms.common.internal.zzu.zzu(metadataChangeSet);
    }

    public void zzct(int i) {
        this.zzaey = Integer.valueOf(i);
    }

    public void zzcv(String str) {
        this.zzadv = (String) com.google.android.gms.common.internal.zzu.zzu(str);
    }
}
