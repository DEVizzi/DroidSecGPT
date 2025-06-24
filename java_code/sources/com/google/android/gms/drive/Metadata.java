package com.google.android.gms.drive;

import com.google.android.gms.common.data.Freezable;
import com.google.android.gms.drive.metadata.CustomPropertyKey;
import com.google.android.gms.drive.metadata.MetadataField;
import com.google.android.gms.drive.metadata.internal.AppVisibleCustomProperties;
import com.google.android.gms.internal.zzlo;
import com.google.android.gms.internal.zzlq;
import com.google.android.gms.internal.zzls;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
/* loaded from: classes.dex */
public abstract class Metadata implements Freezable<Metadata> {
    public static final int CONTENT_AVAILABLE_LOCALLY = 1;
    public static final int CONTENT_NOT_AVAILABLE_LOCALLY = 0;

    public String getAlternateLink() {
        return (String) zza(zzlo.zzagL);
    }

    public int getContentAvailability() {
        Integer num = (Integer) zza(zzls.zzahE);
        if (num == null) {
            return 0;
        }
        return num.intValue();
    }

    public Date getCreatedDate() {
        return (Date) zza(zzlq.zzahy);
    }

    public Map<CustomPropertyKey, String> getCustomProperties() {
        AppVisibleCustomProperties appVisibleCustomProperties = (AppVisibleCustomProperties) zza(zzlo.zzagM);
        return appVisibleCustomProperties == null ? Collections.emptyMap() : appVisibleCustomProperties.zzpT();
    }

    public String getDescription() {
        return (String) zza(zzlo.zzagN);
    }

    public DriveId getDriveId() {
        return (DriveId) zza(zzlo.zzagK);
    }

    public String getEmbedLink() {
        return (String) zza(zzlo.zzagO);
    }

    public String getFileExtension() {
        return (String) zza(zzlo.zzagP);
    }

    public long getFileSize() {
        return ((Long) zza(zzlo.zzagQ)).longValue();
    }

    public Date getLastViewedByMeDate() {
        return (Date) zza(zzlq.zzahz);
    }

    public String getMimeType() {
        return (String) zza(zzlo.zzahg);
    }

    public Date getModifiedByMeDate() {
        return (Date) zza(zzlq.zzahB);
    }

    public Date getModifiedDate() {
        return (Date) zza(zzlq.zzahA);
    }

    public String getOriginalFilename() {
        return (String) zza(zzlo.zzahh);
    }

    public long getQuotaBytesUsed() {
        return ((Long) zza(zzlo.zzahm)).longValue();
    }

    public Date getSharedWithMeDate() {
        return (Date) zza(zzlq.zzahC);
    }

    public String getTitle() {
        return (String) zza(zzlo.zzahp);
    }

    public String getWebContentLink() {
        return (String) zza(zzlo.zzahr);
    }

    public String getWebViewLink() {
        return (String) zza(zzlo.zzahs);
    }

    public boolean isEditable() {
        Boolean bool = (Boolean) zza(zzlo.zzagW);
        if (bool == null) {
            return false;
        }
        return bool.booleanValue();
    }

    public boolean isExplicitlyTrashed() {
        Boolean bool = (Boolean) zza(zzlo.zzagX);
        if (bool == null) {
            return false;
        }
        return bool.booleanValue();
    }

    public boolean isFolder() {
        return DriveFolder.MIME_TYPE.equals(getMimeType());
    }

    public boolean isInAppFolder() {
        Boolean bool = (Boolean) zza(zzlo.zzagU);
        if (bool == null) {
            return false;
        }
        return bool.booleanValue();
    }

    public boolean isPinnable() {
        Boolean bool = (Boolean) zza(zzls.zzahF);
        if (bool == null) {
            return false;
        }
        return bool.booleanValue();
    }

    public boolean isPinned() {
        Boolean bool = (Boolean) zza(zzlo.zzagY);
        if (bool == null) {
            return false;
        }
        return bool.booleanValue();
    }

    public boolean isRestricted() {
        Boolean bool = (Boolean) zza(zzlo.zzaha);
        if (bool == null) {
            return false;
        }
        return bool.booleanValue();
    }

    public boolean isShared() {
        Boolean bool = (Boolean) zza(zzlo.zzahb);
        if (bool == null) {
            return false;
        }
        return bool.booleanValue();
    }

    public boolean isStarred() {
        Boolean bool = (Boolean) zza(zzlo.zzahn);
        if (bool == null) {
            return false;
        }
        return bool.booleanValue();
    }

    public boolean isTrashable() {
        Boolean bool = (Boolean) zza(zzlo.zzahe);
        if (bool == null) {
            return true;
        }
        return bool.booleanValue();
    }

    public boolean isTrashed() {
        Boolean bool = (Boolean) zza(zzlo.zzahq);
        if (bool == null) {
            return false;
        }
        return bool.booleanValue();
    }

    public boolean isViewed() {
        Boolean bool = (Boolean) zza(zzlo.zzahf);
        if (bool == null) {
            return false;
        }
        return bool.booleanValue();
    }

    public abstract <T> T zza(MetadataField<T> metadataField);
}
