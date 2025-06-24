package com.google.android.gms.drive;

import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.drive.metadata.CustomPropertyKey;
import com.google.android.gms.drive.metadata.internal.AppVisibleCustomProperties;
import com.google.android.gms.drive.metadata.internal.MetadataBundle;
import com.google.android.gms.internal.zzlo;
import com.google.android.gms.internal.zzlq;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
/* loaded from: classes.dex */
public final class MetadataChangeSet {
    public static final int CUSTOM_PROPERTY_SIZE_LIMIT_BYTES = 124;
    public static final int INDEXABLE_TEXT_SIZE_LIMIT_BYTES = 131072;
    public static final int MAX_PRIVATE_PROPERTIES_PER_RESOURCE_PER_APP = 30;
    public static final int MAX_PUBLIC_PROPERTIES_PER_RESOURCE = 30;
    public static final int MAX_TOTAL_PROPERTIES_PER_RESOURCE = 100;
    public static final MetadataChangeSet zzads = new MetadataChangeSet(MetadataBundle.zzpX());
    private final MetadataBundle zzadt;

    /* loaded from: classes.dex */
    public static class Builder {
        private final MetadataBundle zzadt = MetadataBundle.zzpX();
        private AppVisibleCustomProperties.zza zzadu;

        private int zzcu(String str) {
            if (str == null) {
                return 0;
            }
            return str.getBytes().length;
        }

        private String zzj(String str, int i, int i2) {
            return String.format("%s must be no more than %d bytes, but is %d bytes.", str, Integer.valueOf(i), Integer.valueOf(i2));
        }

        private void zzk(String str, int i, int i2) {
            zzu.zzb(i2 <= i, zzj(str, i, i2));
        }

        private AppVisibleCustomProperties.zza zzpn() {
            if (this.zzadu == null) {
                this.zzadu = new AppVisibleCustomProperties.zza();
            }
            return this.zzadu;
        }

        public MetadataChangeSet build() {
            if (this.zzadu != null) {
                this.zzadt.zzb(zzlo.zzagM, this.zzadu.zzpU());
            }
            return new MetadataChangeSet(this.zzadt);
        }

        public Builder deleteCustomProperty(CustomPropertyKey key) {
            zzu.zzb(key, "key");
            zzpn().zza(key, null);
            return this;
        }

        public Builder setCustomProperty(CustomPropertyKey key, String value) {
            zzu.zzb(key, "key");
            zzu.zzb(value, "value");
            zzk("The total size of key string and value string of a custom property", MetadataChangeSet.CUSTOM_PROPERTY_SIZE_LIMIT_BYTES, zzcu(key.getKey()) + zzcu(value));
            zzpn().zza(key, value);
            return this;
        }

        public Builder setDescription(String description) {
            this.zzadt.zzb(zzlo.zzagN, description);
            return this;
        }

        public Builder setIndexableText(String text) {
            zzk("Indexable text size", 131072, zzcu(text));
            this.zzadt.zzb(zzlo.zzagT, text);
            return this;
        }

        public Builder setLastViewedByMeDate(Date date) {
            this.zzadt.zzb(zzlq.zzahz, date);
            return this;
        }

        public Builder setMimeType(String mimeType) {
            this.zzadt.zzb(zzlo.zzahg, mimeType);
            return this;
        }

        public Builder setPinned(boolean pinned) {
            this.zzadt.zzb(zzlo.zzagY, Boolean.valueOf(pinned));
            return this;
        }

        public Builder setStarred(boolean starred) {
            this.zzadt.zzb(zzlo.zzahn, Boolean.valueOf(starred));
            return this;
        }

        public Builder setTitle(String title) {
            this.zzadt.zzb(zzlo.zzahp, title);
            return this;
        }

        public Builder setViewed(boolean viewed) {
            this.zzadt.zzb(zzlo.zzahf, Boolean.valueOf(viewed));
            return this;
        }
    }

    public MetadataChangeSet(MetadataBundle bag) {
        this.zzadt = MetadataBundle.zza(bag);
    }

    public Map<CustomPropertyKey, String> getCustomPropertyChangeMap() {
        AppVisibleCustomProperties appVisibleCustomProperties = (AppVisibleCustomProperties) this.zzadt.zza(zzlo.zzagM);
        return appVisibleCustomProperties == null ? Collections.emptyMap() : appVisibleCustomProperties.zzpT();
    }

    public String getDescription() {
        return (String) this.zzadt.zza(zzlo.zzagN);
    }

    public String getIndexableText() {
        return (String) this.zzadt.zza(zzlo.zzagT);
    }

    public Date getLastViewedByMeDate() {
        return (Date) this.zzadt.zza(zzlq.zzahz);
    }

    public String getMimeType() {
        return (String) this.zzadt.zza(zzlo.zzahg);
    }

    public String getTitle() {
        return (String) this.zzadt.zza(zzlo.zzahp);
    }

    public Boolean isPinned() {
        return (Boolean) this.zzadt.zza(zzlo.zzagY);
    }

    public Boolean isStarred() {
        return (Boolean) this.zzadt.zza(zzlo.zzahn);
    }

    public Boolean isViewed() {
        return (Boolean) this.zzadt.zza(zzlo.zzahf);
    }

    public MetadataBundle zzpm() {
        return this.zzadt;
    }
}
