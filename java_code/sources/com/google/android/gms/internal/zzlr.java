package com.google.android.gms.internal;

import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.drive.DriveFolder;
import com.google.android.gms.drive.DriveId;
import java.util.Arrays;
/* loaded from: classes.dex */
public class zzlr extends com.google.android.gms.drive.metadata.internal.zzj<DriveId> {
    public static final zzlr zzahD = new zzlr();

    private zzlr() {
        super("driveId", Arrays.asList("sqlId", "resourceId", "mimeType"), Arrays.asList("dbInstanceId"), 4100000);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.drive.metadata.zza
    /* renamed from: zzm */
    public DriveId zzc(DataHolder dataHolder, int i, int i2) {
        return new DriveId(dataHolder.zzd("resourceId", i, i2), Long.valueOf(dataHolder.zzb("sqlId", i, i2)).longValue(), dataHolder.zznb().getLong("dbInstanceId"), DriveFolder.MIME_TYPE.equals(dataHolder.zzd(zzlo.zzahg.getName(), i, i2)) ? 1 : 0);
    }
}
