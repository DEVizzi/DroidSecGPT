package com.google.android.gms.drive.query;

import com.google.android.gms.drive.DriveId;
import com.google.android.gms.drive.metadata.SearchableCollectionMetadataField;
import com.google.android.gms.drive.metadata.SearchableMetadataField;
import com.google.android.gms.drive.metadata.SearchableOrderedMetadataField;
import com.google.android.gms.drive.metadata.internal.AppVisibleCustomProperties;
import com.google.android.gms.internal.zzlo;
import com.google.android.gms.internal.zzlq;
import java.util.Date;
/* loaded from: classes.dex */
public class SearchableField {
    public static final SearchableMetadataField<String> TITLE = zzlo.zzahp;
    public static final SearchableMetadataField<String> MIME_TYPE = zzlo.zzahg;
    public static final SearchableMetadataField<Boolean> TRASHED = zzlo.zzahq;
    public static final SearchableCollectionMetadataField<DriveId> PARENTS = zzlo.zzahl;
    public static final SearchableOrderedMetadataField<Date> zzahM = zzlq.zzahC;
    public static final SearchableMetadataField<Boolean> STARRED = zzlo.zzahn;
    public static final SearchableOrderedMetadataField<Date> MODIFIED_DATE = zzlq.zzahA;
    public static final SearchableOrderedMetadataField<Date> LAST_VIEWED_BY_ME = zzlq.zzahz;
    public static final SearchableMetadataField<Boolean> IS_PINNED = zzlo.zzagY;
    public static final SearchableMetadataField<AppVisibleCustomProperties> zzahN = zzlo.zzagM;
}
