package com.google.android.gms.internal;

import com.google.android.gms.common.data.BitmapTeleporter;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.drive.DriveId;
import com.google.android.gms.drive.DriveSpace;
import com.google.android.gms.drive.metadata.MetadataField;
import com.google.android.gms.drive.metadata.SearchableMetadataField;
import com.google.android.gms.drive.metadata.SortableMetadataField;
import com.google.android.gms.drive.metadata.internal.AppVisibleCustomProperties;
import com.google.android.gms.plus.PlusShare;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
/* loaded from: classes.dex */
public class zzlo {
    public static final MetadataField<DriveId> zzagK = zzlr.zzahD;
    public static final MetadataField<String> zzagL = new com.google.android.gms.drive.metadata.internal.zzo("alternateLink", 4300000);
    public static final zza zzagM = new zza(5000000);
    public static final MetadataField<String> zzagN = new com.google.android.gms.drive.metadata.internal.zzo(PlusShare.KEY_CONTENT_DEEP_LINK_METADATA_DESCRIPTION, 4300000);
    public static final MetadataField<String> zzagO = new com.google.android.gms.drive.metadata.internal.zzo("embedLink", 4300000);
    public static final MetadataField<String> zzagP = new com.google.android.gms.drive.metadata.internal.zzo("fileExtension", 4300000);
    public static final MetadataField<Long> zzagQ = new com.google.android.gms.drive.metadata.internal.zzg("fileSize", 4300000);
    public static final MetadataField<String> zzagR = new com.google.android.gms.drive.metadata.internal.zzo("folderColorRgb", 7500000);
    public static final MetadataField<Boolean> zzagS = new com.google.android.gms.drive.metadata.internal.zzb("hasThumbnail", 4300000);
    public static final MetadataField<String> zzagT = new com.google.android.gms.drive.metadata.internal.zzo("indexableText", 4300000);
    public static final MetadataField<Boolean> zzagU = new com.google.android.gms.drive.metadata.internal.zzb("isAppData", 4300000);
    public static final MetadataField<Boolean> zzagV = new com.google.android.gms.drive.metadata.internal.zzb("isCopyable", 4300000);
    public static final MetadataField<Boolean> zzagW = new com.google.android.gms.drive.metadata.internal.zzb("isEditable", 4100000);
    public static final MetadataField<Boolean> zzagX = new com.google.android.gms.drive.metadata.internal.zzb("isExplicitlyTrashed", Collections.singleton("trashed"), Collections.emptySet(), 7000000) { // from class: com.google.android.gms.internal.zzlo.1
        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.drive.metadata.internal.zzb, com.google.android.gms.drive.metadata.zza
        /* renamed from: zze */
        public Boolean zzc(DataHolder dataHolder, int i, int i2) {
            return Boolean.valueOf(dataHolder.zzc("trashed", i, i2) == 2);
        }
    };
    public static final zzb zzagY = new zzb("isPinned", 4100000);
    public static final MetadataField<Boolean> zzagZ = new com.google.android.gms.drive.metadata.internal.zzb("isOpenable", 7200000);
    public static final MetadataField<Boolean> zzaha = new com.google.android.gms.drive.metadata.internal.zzb("isRestricted", 4300000);
    public static final MetadataField<Boolean> zzahb = new com.google.android.gms.drive.metadata.internal.zzb("isShared", 4300000);
    public static final MetadataField<Boolean> zzahc = new com.google.android.gms.drive.metadata.internal.zzb("isGooglePhotosFolder", 7000000);
    public static final MetadataField<Boolean> zzahd = new com.google.android.gms.drive.metadata.internal.zzb("isGooglePhotosRootFolder", 7000000);
    public static final MetadataField<Boolean> zzahe = new com.google.android.gms.drive.metadata.internal.zzb("isTrashable", 4400000);
    public static final MetadataField<Boolean> zzahf = new com.google.android.gms.drive.metadata.internal.zzb("isViewed", 4300000);
    public static final zzc zzahg = new zzc(4100000);
    public static final MetadataField<String> zzahh = new com.google.android.gms.drive.metadata.internal.zzo("originalFilename", 4300000);
    public static final com.google.android.gms.drive.metadata.zzb<String> zzahi = new com.google.android.gms.drive.metadata.internal.zzn("ownerNames", 4300000);
    public static final com.google.android.gms.drive.metadata.internal.zzp zzahj = new com.google.android.gms.drive.metadata.internal.zzp("lastModifyingUser", 6000000);
    public static final com.google.android.gms.drive.metadata.internal.zzp zzahk = new com.google.android.gms.drive.metadata.internal.zzp("sharingUser", 6000000);
    public static final com.google.android.gms.drive.metadata.internal.zzl zzahl = new com.google.android.gms.drive.metadata.internal.zzl(4100000);
    public static final zzd zzahm = new zzd("quotaBytesUsed", 4300000);
    public static final zzf zzahn = new zzf("starred", 4100000);
    public static final MetadataField<BitmapTeleporter> zzaho = new com.google.android.gms.drive.metadata.internal.zzj<BitmapTeleporter>("thumbnail", Collections.emptySet(), Collections.emptySet(), 4400000) { // from class: com.google.android.gms.internal.zzlo.2
        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.drive.metadata.zza
        /* renamed from: zzk */
        public BitmapTeleporter zzc(DataHolder dataHolder, int i, int i2) {
            throw new IllegalStateException("Thumbnail field is write only");
        }
    };
    public static final zzg zzahp = new zzg(PlusShare.KEY_CONTENT_DEEP_LINK_METADATA_TITLE, 4100000);
    public static final zzh zzahq = new zzh("trashed", 4100000);
    public static final MetadataField<String> zzahr = new com.google.android.gms.drive.metadata.internal.zzo("webContentLink", 4300000);
    public static final MetadataField<String> zzahs = new com.google.android.gms.drive.metadata.internal.zzo("webViewLink", 4300000);
    public static final MetadataField<String> zzaht = new com.google.android.gms.drive.metadata.internal.zzo("uniqueIdentifier", 5000000);
    public static final com.google.android.gms.drive.metadata.internal.zzb zzahu = new com.google.android.gms.drive.metadata.internal.zzb("writersCanShare", 6000000);
    public static final MetadataField<String> zzahv = new com.google.android.gms.drive.metadata.internal.zzo("role", 6000000);
    public static final MetadataField<String> zzahw = new com.google.android.gms.drive.metadata.internal.zzo("md5Checksum", 7000000);
    public static final zze zzahx = new zze(7000000);

    /* loaded from: classes.dex */
    public static class zza extends zzlp implements SearchableMetadataField<AppVisibleCustomProperties> {
        public zza(int i) {
            super(i);
        }
    }

    /* loaded from: classes.dex */
    public static class zzb extends com.google.android.gms.drive.metadata.internal.zzb implements SearchableMetadataField<Boolean> {
        public zzb(String str, int i) {
            super(str, i);
        }
    }

    /* loaded from: classes.dex */
    public static class zzc extends com.google.android.gms.drive.metadata.internal.zzo implements SearchableMetadataField<String> {
        public zzc(int i) {
            super("mimeType", i);
        }
    }

    /* loaded from: classes.dex */
    public static class zzd extends com.google.android.gms.drive.metadata.internal.zzg implements SortableMetadataField<Long> {
        public zzd(String str, int i) {
            super(str, i);
        }
    }

    /* loaded from: classes.dex */
    public static class zze extends com.google.android.gms.drive.metadata.internal.zzi<DriveSpace> {
        public zze(int i) {
            super("spaces", Arrays.asList("inDriveSpace", "isAppData", "inGooglePhotosSpace"), Collections.emptySet(), i);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.drive.metadata.zzb, com.google.android.gms.drive.metadata.zza
        /* renamed from: zzd */
        public Collection<DriveSpace> zzc(DataHolder dataHolder, int i, int i2) {
            ArrayList arrayList = new ArrayList();
            if (dataHolder.zze("inDriveSpace", i, i2)) {
                arrayList.add(DriveSpace.zzadi);
            }
            if (dataHolder.zze("isAppData", i, i2)) {
                arrayList.add(DriveSpace.zzadj);
            }
            if (dataHolder.zze("inGooglePhotosSpace", i, i2)) {
                arrayList.add(DriveSpace.zzadk);
            }
            return arrayList;
        }
    }

    /* loaded from: classes.dex */
    public static class zzf extends com.google.android.gms.drive.metadata.internal.zzb implements SearchableMetadataField<Boolean> {
        public zzf(String str, int i) {
            super(str, i);
        }
    }

    /* loaded from: classes.dex */
    public static class zzg extends com.google.android.gms.drive.metadata.internal.zzo implements SearchableMetadataField<String>, SortableMetadataField<String> {
        public zzg(String str, int i) {
            super(str, i);
        }
    }

    /* loaded from: classes.dex */
    public static class zzh extends com.google.android.gms.drive.metadata.internal.zzb implements SearchableMetadataField<Boolean> {
        public zzh(String str, int i) {
            super(str, i);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.drive.metadata.internal.zzb, com.google.android.gms.drive.metadata.zza
        /* renamed from: zze */
        public Boolean zzc(DataHolder dataHolder, int i, int i2) {
            return Boolean.valueOf(dataHolder.zzc(getName(), i, i2) != 0);
        }
    }
}
