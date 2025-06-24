package com.google.android.gms.internal;

import com.google.android.gms.drive.metadata.SearchableOrderedMetadataField;
import com.google.android.gms.drive.metadata.SortableMetadataField;
import java.util.Date;
/* loaded from: classes.dex */
public class zzlq {
    public static final zza zzahy = new zza("created", 4100000);
    public static final zzb zzahz = new zzb("lastOpenedTime", 4300000);
    public static final zzd zzahA = new zzd("modified", 4100000);
    public static final zzc zzahB = new zzc("modifiedByMe", 4100000);
    public static final zze zzahC = new zze("sharedWithMe", 4100000);

    /* loaded from: classes.dex */
    public static class zza extends com.google.android.gms.drive.metadata.internal.zzd implements SortableMetadataField<Date> {
        public zza(String str, int i) {
            super(str, i);
        }
    }

    /* loaded from: classes.dex */
    public static class zzb extends com.google.android.gms.drive.metadata.internal.zzd implements SearchableOrderedMetadataField<Date>, SortableMetadataField<Date> {
        public zzb(String str, int i) {
            super(str, i);
        }
    }

    /* loaded from: classes.dex */
    public static class zzc extends com.google.android.gms.drive.metadata.internal.zzd implements SortableMetadataField<Date> {
        public zzc(String str, int i) {
            super(str, i);
        }
    }

    /* loaded from: classes.dex */
    public static class zzd extends com.google.android.gms.drive.metadata.internal.zzd implements SearchableOrderedMetadataField<Date>, SortableMetadataField<Date> {
        public zzd(String str, int i) {
            super(str, i);
        }
    }

    /* loaded from: classes.dex */
    public static class zze extends com.google.android.gms.drive.metadata.internal.zzd implements SearchableOrderedMetadataField<Date>, SortableMetadataField<Date> {
        public zze(String str, int i) {
            super(str, i);
        }
    }
}
