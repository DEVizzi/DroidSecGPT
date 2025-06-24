package com.google.android.gms.plus.internal.model.people;

import android.os.Parcel;
import com.google.android.gms.common.Scopes;
import com.google.android.gms.common.server.converter.StringToIntConverter;
import com.google.android.gms.common.server.response.FastJsonResponse;
import com.google.android.gms.common.server.response.FastSafeParcelableJsonResponse;
import com.google.android.gms.fitness.FitnessActivities;
import com.google.android.gms.plus.PlusShare;
import com.google.android.gms.plus.model.people.Person;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
/* loaded from: classes.dex */
public final class PersonEntity extends FastSafeParcelableJsonResponse implements Person {
    public static final com.google.android.gms.plus.internal.model.people.zza CREATOR = new com.google.android.gms.plus.internal.model.people.zza();
    private static final HashMap<String, FastJsonResponse.Field<?, ?>> zzaHP = new HashMap<>();
    final int zzCY;
    String zzF;
    String zzKI;
    String zzRA;
    final Set<Integer> zzaHQ;
    String zzaIO;
    AgeRangeEntity zzaIP;
    String zzaIQ;
    String zzaIR;
    int zzaIS;
    CoverEntity zzaIT;
    String zzaIU;
    ImageEntity zzaIV;
    boolean zzaIW;
    NameEntity zzaIX;
    String zzaIY;
    int zzaIZ;
    List<OrganizationsEntity> zzaJa;
    List<PlacesLivedEntity> zzaJb;
    int zzaJc;
    int zzaJd;
    String zzaJe;
    List<UrlsEntity> zzaJf;
    boolean zzaJg;
    String zzadI;
    int zzsC;

    /* loaded from: classes.dex */
    public static final class AgeRangeEntity extends FastSafeParcelableJsonResponse implements Person.AgeRange {
        public static final zzb CREATOR = new zzb();
        private static final HashMap<String, FastJsonResponse.Field<?, ?>> zzaHP = new HashMap<>();
        final int zzCY;
        final Set<Integer> zzaHQ;
        int zzaJh;
        int zzaJi;

        static {
            zzaHP.put("max", FastJsonResponse.Field.zzi("max", 2));
            zzaHP.put("min", FastJsonResponse.Field.zzi("min", 3));
        }

        public AgeRangeEntity() {
            this.zzCY = 1;
            this.zzaHQ = new HashSet();
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public AgeRangeEntity(Set<Integer> indicatorSet, int versionCode, int max, int min) {
            this.zzaHQ = indicatorSet;
            this.zzCY = versionCode;
            this.zzaJh = max;
            this.zzaJi = min;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            zzb zzbVar = CREATOR;
            return 0;
        }

        public boolean equals(Object obj) {
            if (obj instanceof AgeRangeEntity) {
                if (this == obj) {
                    return true;
                }
                AgeRangeEntity ageRangeEntity = (AgeRangeEntity) obj;
                for (FastJsonResponse.Field<?, ?> field : zzaHP.values()) {
                    if (zza(field)) {
                        if (ageRangeEntity.zza(field) && zzb(field).equals(ageRangeEntity.zzb(field))) {
                        }
                        return false;
                    } else if (ageRangeEntity.zza(field)) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }

        @Override // com.google.android.gms.plus.model.people.Person.AgeRange
        public int getMax() {
            return this.zzaJh;
        }

        @Override // com.google.android.gms.plus.model.people.Person.AgeRange
        public int getMin() {
            return this.zzaJi;
        }

        @Override // com.google.android.gms.plus.model.people.Person.AgeRange
        public boolean hasMax() {
            return this.zzaHQ.contains(2);
        }

        @Override // com.google.android.gms.plus.model.people.Person.AgeRange
        public boolean hasMin() {
            return this.zzaHQ.contains(3);
        }

        public int hashCode() {
            int i = 0;
            Iterator<FastJsonResponse.Field<?, ?>> it = zzaHP.values().iterator();
            while (true) {
                int i2 = i;
                if (!it.hasNext()) {
                    return i2;
                }
                FastJsonResponse.Field<?, ?> next = it.next();
                if (zza(next)) {
                    i = zzb(next).hashCode() + i2 + next.zzot();
                } else {
                    i = i2;
                }
            }
        }

        @Override // com.google.android.gms.common.data.Freezable
        public boolean isDataValid() {
            return true;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel out, int flags) {
            zzb zzbVar = CREATOR;
            zzb.zza(this, out, flags);
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        protected boolean zza(FastJsonResponse.Field field) {
            return this.zzaHQ.contains(Integer.valueOf(field.zzot()));
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        protected Object zzb(FastJsonResponse.Field field) {
            switch (field.zzot()) {
                case 2:
                    return Integer.valueOf(this.zzaJh);
                case 3:
                    return Integer.valueOf(this.zzaJi);
                default:
                    throw new IllegalStateException("Unknown safe parcelable id=" + field.zzot());
            }
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        /* renamed from: zzxF */
        public HashMap<String, FastJsonResponse.Field<?, ?>> zzom() {
            return zzaHP;
        }

        @Override // com.google.android.gms.common.data.Freezable
        /* renamed from: zzxK */
        public AgeRangeEntity freeze() {
            return this;
        }
    }

    /* loaded from: classes.dex */
    public static final class CoverEntity extends FastSafeParcelableJsonResponse implements Person.Cover {
        public static final zzc CREATOR = new zzc();
        private static final HashMap<String, FastJsonResponse.Field<?, ?>> zzaHP = new HashMap<>();
        final int zzCY;
        final Set<Integer> zzaHQ;
        CoverInfoEntity zzaJj;
        CoverPhotoEntity zzaJk;
        int zzaJl;

        /* loaded from: classes.dex */
        public static final class CoverInfoEntity extends FastSafeParcelableJsonResponse implements Person.Cover.CoverInfo {
            public static final zzd CREATOR = new zzd();
            private static final HashMap<String, FastJsonResponse.Field<?, ?>> zzaHP = new HashMap<>();
            final int zzCY;
            final Set<Integer> zzaHQ;
            int zzaJm;
            int zzaJn;

            static {
                zzaHP.put("leftImageOffset", FastJsonResponse.Field.zzi("leftImageOffset", 2));
                zzaHP.put("topImageOffset", FastJsonResponse.Field.zzi("topImageOffset", 3));
            }

            public CoverInfoEntity() {
                this.zzCY = 1;
                this.zzaHQ = new HashSet();
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            public CoverInfoEntity(Set<Integer> indicatorSet, int versionCode, int leftImageOffset, int topImageOffset) {
                this.zzaHQ = indicatorSet;
                this.zzCY = versionCode;
                this.zzaJm = leftImageOffset;
                this.zzaJn = topImageOffset;
            }

            @Override // android.os.Parcelable
            public int describeContents() {
                zzd zzdVar = CREATOR;
                return 0;
            }

            public boolean equals(Object obj) {
                if (obj instanceof CoverInfoEntity) {
                    if (this == obj) {
                        return true;
                    }
                    CoverInfoEntity coverInfoEntity = (CoverInfoEntity) obj;
                    for (FastJsonResponse.Field<?, ?> field : zzaHP.values()) {
                        if (zza(field)) {
                            if (coverInfoEntity.zza(field) && zzb(field).equals(coverInfoEntity.zzb(field))) {
                            }
                            return false;
                        } else if (coverInfoEntity.zza(field)) {
                            return false;
                        }
                    }
                    return true;
                }
                return false;
            }

            @Override // com.google.android.gms.plus.model.people.Person.Cover.CoverInfo
            public int getLeftImageOffset() {
                return this.zzaJm;
            }

            @Override // com.google.android.gms.plus.model.people.Person.Cover.CoverInfo
            public int getTopImageOffset() {
                return this.zzaJn;
            }

            @Override // com.google.android.gms.plus.model.people.Person.Cover.CoverInfo
            public boolean hasLeftImageOffset() {
                return this.zzaHQ.contains(2);
            }

            @Override // com.google.android.gms.plus.model.people.Person.Cover.CoverInfo
            public boolean hasTopImageOffset() {
                return this.zzaHQ.contains(3);
            }

            public int hashCode() {
                int i = 0;
                Iterator<FastJsonResponse.Field<?, ?>> it = zzaHP.values().iterator();
                while (true) {
                    int i2 = i;
                    if (!it.hasNext()) {
                        return i2;
                    }
                    FastJsonResponse.Field<?, ?> next = it.next();
                    if (zza(next)) {
                        i = zzb(next).hashCode() + i2 + next.zzot();
                    } else {
                        i = i2;
                    }
                }
            }

            @Override // com.google.android.gms.common.data.Freezable
            public boolean isDataValid() {
                return true;
            }

            @Override // android.os.Parcelable
            public void writeToParcel(Parcel out, int flags) {
                zzd zzdVar = CREATOR;
                zzd.zza(this, out, flags);
            }

            @Override // com.google.android.gms.common.server.response.FastJsonResponse
            protected boolean zza(FastJsonResponse.Field field) {
                return this.zzaHQ.contains(Integer.valueOf(field.zzot()));
            }

            @Override // com.google.android.gms.common.server.response.FastJsonResponse
            protected Object zzb(FastJsonResponse.Field field) {
                switch (field.zzot()) {
                    case 2:
                        return Integer.valueOf(this.zzaJm);
                    case 3:
                        return Integer.valueOf(this.zzaJn);
                    default:
                        throw new IllegalStateException("Unknown safe parcelable id=" + field.zzot());
                }
            }

            @Override // com.google.android.gms.common.server.response.FastJsonResponse
            /* renamed from: zzxF */
            public HashMap<String, FastJsonResponse.Field<?, ?>> zzom() {
                return zzaHP;
            }

            @Override // com.google.android.gms.common.data.Freezable
            /* renamed from: zzxM */
            public CoverInfoEntity freeze() {
                return this;
            }
        }

        /* loaded from: classes.dex */
        public static final class CoverPhotoEntity extends FastSafeParcelableJsonResponse implements Person.Cover.CoverPhoto {
            public static final zze CREATOR = new zze();
            private static final HashMap<String, FastJsonResponse.Field<?, ?>> zzaHP = new HashMap<>();
            final int zzCY;
            String zzF;
            final Set<Integer> zzaHQ;
            int zznM;
            int zznN;

            static {
                zzaHP.put("height", FastJsonResponse.Field.zzi("height", 2));
                zzaHP.put(PlusShare.KEY_CALL_TO_ACTION_URL, FastJsonResponse.Field.zzl(PlusShare.KEY_CALL_TO_ACTION_URL, 3));
                zzaHP.put("width", FastJsonResponse.Field.zzi("width", 4));
            }

            public CoverPhotoEntity() {
                this.zzCY = 1;
                this.zzaHQ = new HashSet();
            }

            /* JADX INFO: Access modifiers changed from: package-private */
            public CoverPhotoEntity(Set<Integer> indicatorSet, int versionCode, int height, String url, int width) {
                this.zzaHQ = indicatorSet;
                this.zzCY = versionCode;
                this.zznN = height;
                this.zzF = url;
                this.zznM = width;
            }

            @Override // android.os.Parcelable
            public int describeContents() {
                zze zzeVar = CREATOR;
                return 0;
            }

            public boolean equals(Object obj) {
                if (obj instanceof CoverPhotoEntity) {
                    if (this == obj) {
                        return true;
                    }
                    CoverPhotoEntity coverPhotoEntity = (CoverPhotoEntity) obj;
                    for (FastJsonResponse.Field<?, ?> field : zzaHP.values()) {
                        if (zza(field)) {
                            if (coverPhotoEntity.zza(field) && zzb(field).equals(coverPhotoEntity.zzb(field))) {
                            }
                            return false;
                        } else if (coverPhotoEntity.zza(field)) {
                            return false;
                        }
                    }
                    return true;
                }
                return false;
            }

            @Override // com.google.android.gms.plus.model.people.Person.Cover.CoverPhoto
            public int getHeight() {
                return this.zznN;
            }

            @Override // com.google.android.gms.plus.model.people.Person.Cover.CoverPhoto
            public String getUrl() {
                return this.zzF;
            }

            @Override // com.google.android.gms.plus.model.people.Person.Cover.CoverPhoto
            public int getWidth() {
                return this.zznM;
            }

            @Override // com.google.android.gms.plus.model.people.Person.Cover.CoverPhoto
            public boolean hasHeight() {
                return this.zzaHQ.contains(2);
            }

            @Override // com.google.android.gms.plus.model.people.Person.Cover.CoverPhoto
            public boolean hasUrl() {
                return this.zzaHQ.contains(3);
            }

            @Override // com.google.android.gms.plus.model.people.Person.Cover.CoverPhoto
            public boolean hasWidth() {
                return this.zzaHQ.contains(4);
            }

            public int hashCode() {
                int i = 0;
                Iterator<FastJsonResponse.Field<?, ?>> it = zzaHP.values().iterator();
                while (true) {
                    int i2 = i;
                    if (!it.hasNext()) {
                        return i2;
                    }
                    FastJsonResponse.Field<?, ?> next = it.next();
                    if (zza(next)) {
                        i = zzb(next).hashCode() + i2 + next.zzot();
                    } else {
                        i = i2;
                    }
                }
            }

            @Override // com.google.android.gms.common.data.Freezable
            public boolean isDataValid() {
                return true;
            }

            @Override // android.os.Parcelable
            public void writeToParcel(Parcel out, int flags) {
                zze zzeVar = CREATOR;
                zze.zza(this, out, flags);
            }

            @Override // com.google.android.gms.common.server.response.FastJsonResponse
            protected boolean zza(FastJsonResponse.Field field) {
                return this.zzaHQ.contains(Integer.valueOf(field.zzot()));
            }

            @Override // com.google.android.gms.common.server.response.FastJsonResponse
            protected Object zzb(FastJsonResponse.Field field) {
                switch (field.zzot()) {
                    case 2:
                        return Integer.valueOf(this.zznN);
                    case 3:
                        return this.zzF;
                    case 4:
                        return Integer.valueOf(this.zznM);
                    default:
                        throw new IllegalStateException("Unknown safe parcelable id=" + field.zzot());
                }
            }

            @Override // com.google.android.gms.common.server.response.FastJsonResponse
            /* renamed from: zzxF */
            public HashMap<String, FastJsonResponse.Field<?, ?>> zzom() {
                return zzaHP;
            }

            @Override // com.google.android.gms.common.data.Freezable
            /* renamed from: zzxN */
            public CoverPhotoEntity freeze() {
                return this;
            }
        }

        static {
            zzaHP.put("coverInfo", FastJsonResponse.Field.zza("coverInfo", 2, CoverInfoEntity.class));
            zzaHP.put("coverPhoto", FastJsonResponse.Field.zza("coverPhoto", 3, CoverPhotoEntity.class));
            zzaHP.put("layout", FastJsonResponse.Field.zza("layout", 4, new StringToIntConverter().zzh("banner", 0), false));
        }

        public CoverEntity() {
            this.zzCY = 1;
            this.zzaHQ = new HashSet();
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public CoverEntity(Set<Integer> indicatorSet, int versionCode, CoverInfoEntity coverInfo, CoverPhotoEntity coverPhoto, int layout) {
            this.zzaHQ = indicatorSet;
            this.zzCY = versionCode;
            this.zzaJj = coverInfo;
            this.zzaJk = coverPhoto;
            this.zzaJl = layout;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            zzc zzcVar = CREATOR;
            return 0;
        }

        public boolean equals(Object obj) {
            if (obj instanceof CoverEntity) {
                if (this == obj) {
                    return true;
                }
                CoverEntity coverEntity = (CoverEntity) obj;
                for (FastJsonResponse.Field<?, ?> field : zzaHP.values()) {
                    if (zza(field)) {
                        if (coverEntity.zza(field) && zzb(field).equals(coverEntity.zzb(field))) {
                        }
                        return false;
                    } else if (coverEntity.zza(field)) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Cover
        public Person.Cover.CoverInfo getCoverInfo() {
            return this.zzaJj;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Cover
        public Person.Cover.CoverPhoto getCoverPhoto() {
            return this.zzaJk;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Cover
        public int getLayout() {
            return this.zzaJl;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Cover
        public boolean hasCoverInfo() {
            return this.zzaHQ.contains(2);
        }

        @Override // com.google.android.gms.plus.model.people.Person.Cover
        public boolean hasCoverPhoto() {
            return this.zzaHQ.contains(3);
        }

        @Override // com.google.android.gms.plus.model.people.Person.Cover
        public boolean hasLayout() {
            return this.zzaHQ.contains(4);
        }

        public int hashCode() {
            int i = 0;
            Iterator<FastJsonResponse.Field<?, ?>> it = zzaHP.values().iterator();
            while (true) {
                int i2 = i;
                if (!it.hasNext()) {
                    return i2;
                }
                FastJsonResponse.Field<?, ?> next = it.next();
                if (zza(next)) {
                    i = zzb(next).hashCode() + i2 + next.zzot();
                } else {
                    i = i2;
                }
            }
        }

        @Override // com.google.android.gms.common.data.Freezable
        public boolean isDataValid() {
            return true;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel out, int flags) {
            zzc zzcVar = CREATOR;
            zzc.zza(this, out, flags);
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        protected boolean zza(FastJsonResponse.Field field) {
            return this.zzaHQ.contains(Integer.valueOf(field.zzot()));
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        protected Object zzb(FastJsonResponse.Field field) {
            switch (field.zzot()) {
                case 2:
                    return this.zzaJj;
                case 3:
                    return this.zzaJk;
                case 4:
                    return Integer.valueOf(this.zzaJl);
                default:
                    throw new IllegalStateException("Unknown safe parcelable id=" + field.zzot());
            }
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        /* renamed from: zzxF */
        public HashMap<String, FastJsonResponse.Field<?, ?>> zzom() {
            return zzaHP;
        }

        @Override // com.google.android.gms.common.data.Freezable
        /* renamed from: zzxL */
        public CoverEntity freeze() {
            return this;
        }
    }

    /* loaded from: classes.dex */
    public static final class ImageEntity extends FastSafeParcelableJsonResponse implements Person.Image {
        public static final zzf CREATOR = new zzf();
        private static final HashMap<String, FastJsonResponse.Field<?, ?>> zzaHP = new HashMap<>();
        final int zzCY;
        String zzF;
        final Set<Integer> zzaHQ;

        static {
            zzaHP.put(PlusShare.KEY_CALL_TO_ACTION_URL, FastJsonResponse.Field.zzl(PlusShare.KEY_CALL_TO_ACTION_URL, 2));
        }

        public ImageEntity() {
            this.zzCY = 1;
            this.zzaHQ = new HashSet();
        }

        public ImageEntity(String url) {
            this.zzaHQ = new HashSet();
            this.zzCY = 1;
            this.zzF = url;
            this.zzaHQ.add(2);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public ImageEntity(Set<Integer> indicatorSet, int versionCode, String url) {
            this.zzaHQ = indicatorSet;
            this.zzCY = versionCode;
            this.zzF = url;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            zzf zzfVar = CREATOR;
            return 0;
        }

        public boolean equals(Object obj) {
            if (obj instanceof ImageEntity) {
                if (this == obj) {
                    return true;
                }
                ImageEntity imageEntity = (ImageEntity) obj;
                for (FastJsonResponse.Field<?, ?> field : zzaHP.values()) {
                    if (zza(field)) {
                        if (imageEntity.zza(field) && zzb(field).equals(imageEntity.zzb(field))) {
                        }
                        return false;
                    } else if (imageEntity.zza(field)) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Image
        public String getUrl() {
            return this.zzF;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Image
        public boolean hasUrl() {
            return this.zzaHQ.contains(2);
        }

        public int hashCode() {
            int i = 0;
            Iterator<FastJsonResponse.Field<?, ?>> it = zzaHP.values().iterator();
            while (true) {
                int i2 = i;
                if (!it.hasNext()) {
                    return i2;
                }
                FastJsonResponse.Field<?, ?> next = it.next();
                if (zza(next)) {
                    i = zzb(next).hashCode() + i2 + next.zzot();
                } else {
                    i = i2;
                }
            }
        }

        @Override // com.google.android.gms.common.data.Freezable
        public boolean isDataValid() {
            return true;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel out, int flags) {
            zzf zzfVar = CREATOR;
            zzf.zza(this, out, flags);
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        protected boolean zza(FastJsonResponse.Field field) {
            return this.zzaHQ.contains(Integer.valueOf(field.zzot()));
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        protected Object zzb(FastJsonResponse.Field field) {
            switch (field.zzot()) {
                case 2:
                    return this.zzF;
                default:
                    throw new IllegalStateException("Unknown safe parcelable id=" + field.zzot());
            }
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        /* renamed from: zzxF */
        public HashMap<String, FastJsonResponse.Field<?, ?>> zzom() {
            return zzaHP;
        }

        @Override // com.google.android.gms.common.data.Freezable
        /* renamed from: zzxO */
        public ImageEntity freeze() {
            return this;
        }
    }

    /* loaded from: classes.dex */
    public static final class NameEntity extends FastSafeParcelableJsonResponse implements Person.Name {
        public static final zzg CREATOR = new zzg();
        private static final HashMap<String, FastJsonResponse.Field<?, ?>> zzaHP = new HashMap<>();
        final int zzCY;
        final Set<Integer> zzaHQ;
        String zzaIo;
        String zzaIr;
        String zzaJo;
        String zzaJp;
        String zzaJq;
        String zzaJr;

        static {
            zzaHP.put("familyName", FastJsonResponse.Field.zzl("familyName", 2));
            zzaHP.put("formatted", FastJsonResponse.Field.zzl("formatted", 3));
            zzaHP.put("givenName", FastJsonResponse.Field.zzl("givenName", 4));
            zzaHP.put("honorificPrefix", FastJsonResponse.Field.zzl("honorificPrefix", 5));
            zzaHP.put("honorificSuffix", FastJsonResponse.Field.zzl("honorificSuffix", 6));
            zzaHP.put("middleName", FastJsonResponse.Field.zzl("middleName", 7));
        }

        public NameEntity() {
            this.zzCY = 1;
            this.zzaHQ = new HashSet();
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public NameEntity(Set<Integer> indicatorSet, int versionCode, String familyName, String formatted, String givenName, String honorificPrefix, String honorificSuffix, String middleName) {
            this.zzaHQ = indicatorSet;
            this.zzCY = versionCode;
            this.zzaIo = familyName;
            this.zzaJo = formatted;
            this.zzaIr = givenName;
            this.zzaJp = honorificPrefix;
            this.zzaJq = honorificSuffix;
            this.zzaJr = middleName;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            zzg zzgVar = CREATOR;
            return 0;
        }

        public boolean equals(Object obj) {
            if (obj instanceof NameEntity) {
                if (this == obj) {
                    return true;
                }
                NameEntity nameEntity = (NameEntity) obj;
                for (FastJsonResponse.Field<?, ?> field : zzaHP.values()) {
                    if (zza(field)) {
                        if (nameEntity.zza(field) && zzb(field).equals(nameEntity.zzb(field))) {
                        }
                        return false;
                    } else if (nameEntity.zza(field)) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Name
        public String getFamilyName() {
            return this.zzaIo;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Name
        public String getFormatted() {
            return this.zzaJo;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Name
        public String getGivenName() {
            return this.zzaIr;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Name
        public String getHonorificPrefix() {
            return this.zzaJp;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Name
        public String getHonorificSuffix() {
            return this.zzaJq;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Name
        public String getMiddleName() {
            return this.zzaJr;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Name
        public boolean hasFamilyName() {
            return this.zzaHQ.contains(2);
        }

        @Override // com.google.android.gms.plus.model.people.Person.Name
        public boolean hasFormatted() {
            return this.zzaHQ.contains(3);
        }

        @Override // com.google.android.gms.plus.model.people.Person.Name
        public boolean hasGivenName() {
            return this.zzaHQ.contains(4);
        }

        @Override // com.google.android.gms.plus.model.people.Person.Name
        public boolean hasHonorificPrefix() {
            return this.zzaHQ.contains(5);
        }

        @Override // com.google.android.gms.plus.model.people.Person.Name
        public boolean hasHonorificSuffix() {
            return this.zzaHQ.contains(6);
        }

        @Override // com.google.android.gms.plus.model.people.Person.Name
        public boolean hasMiddleName() {
            return this.zzaHQ.contains(7);
        }

        public int hashCode() {
            int i = 0;
            Iterator<FastJsonResponse.Field<?, ?>> it = zzaHP.values().iterator();
            while (true) {
                int i2 = i;
                if (!it.hasNext()) {
                    return i2;
                }
                FastJsonResponse.Field<?, ?> next = it.next();
                if (zza(next)) {
                    i = zzb(next).hashCode() + i2 + next.zzot();
                } else {
                    i = i2;
                }
            }
        }

        @Override // com.google.android.gms.common.data.Freezable
        public boolean isDataValid() {
            return true;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel out, int flags) {
            zzg zzgVar = CREATOR;
            zzg.zza(this, out, flags);
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        protected boolean zza(FastJsonResponse.Field field) {
            return this.zzaHQ.contains(Integer.valueOf(field.zzot()));
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        protected Object zzb(FastJsonResponse.Field field) {
            switch (field.zzot()) {
                case 2:
                    return this.zzaIo;
                case 3:
                    return this.zzaJo;
                case 4:
                    return this.zzaIr;
                case 5:
                    return this.zzaJp;
                case 6:
                    return this.zzaJq;
                case 7:
                    return this.zzaJr;
                default:
                    throw new IllegalStateException("Unknown safe parcelable id=" + field.zzot());
            }
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        /* renamed from: zzxF */
        public HashMap<String, FastJsonResponse.Field<?, ?>> zzom() {
            return zzaHP;
        }

        @Override // com.google.android.gms.common.data.Freezable
        /* renamed from: zzxP */
        public NameEntity freeze() {
            return this;
        }
    }

    /* loaded from: classes.dex */
    public static final class OrganizationsEntity extends FastSafeParcelableJsonResponse implements Person.Organizations {
        public static final zzh CREATOR = new zzh();
        private static final HashMap<String, FastJsonResponse.Field<?, ?>> zzaHP = new HashMap<>();
        String mName;
        final int zzCY;
        int zzSq;
        final Set<Integer> zzaHQ;
        String zzaID;
        String zzaIn;
        String zzaJs;
        String zzaJt;
        boolean zzaJu;
        String zzadv;
        String zzakM;

        static {
            zzaHP.put("department", FastJsonResponse.Field.zzl("department", 2));
            zzaHP.put(PlusShare.KEY_CONTENT_DEEP_LINK_METADATA_DESCRIPTION, FastJsonResponse.Field.zzl(PlusShare.KEY_CONTENT_DEEP_LINK_METADATA_DESCRIPTION, 3));
            zzaHP.put("endDate", FastJsonResponse.Field.zzl("endDate", 4));
            zzaHP.put("location", FastJsonResponse.Field.zzl("location", 5));
            zzaHP.put("name", FastJsonResponse.Field.zzl("name", 6));
            zzaHP.put("primary", FastJsonResponse.Field.zzk("primary", 7));
            zzaHP.put("startDate", FastJsonResponse.Field.zzl("startDate", 8));
            zzaHP.put(PlusShare.KEY_CONTENT_DEEP_LINK_METADATA_TITLE, FastJsonResponse.Field.zzl(PlusShare.KEY_CONTENT_DEEP_LINK_METADATA_TITLE, 9));
            zzaHP.put("type", FastJsonResponse.Field.zza("type", 10, new StringToIntConverter().zzh("work", 0).zzh("school", 1), false));
        }

        public OrganizationsEntity() {
            this.zzCY = 1;
            this.zzaHQ = new HashSet();
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public OrganizationsEntity(Set<Integer> indicatorSet, int versionCode, String department, String description, String endDate, String location, String name, boolean primary, String startDate, String title, int type) {
            this.zzaHQ = indicatorSet;
            this.zzCY = versionCode;
            this.zzaJs = department;
            this.zzakM = description;
            this.zzaIn = endDate;
            this.zzaJt = location;
            this.mName = name;
            this.zzaJu = primary;
            this.zzaID = startDate;
            this.zzadv = title;
            this.zzSq = type;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            zzh zzhVar = CREATOR;
            return 0;
        }

        public boolean equals(Object obj) {
            if (obj instanceof OrganizationsEntity) {
                if (this == obj) {
                    return true;
                }
                OrganizationsEntity organizationsEntity = (OrganizationsEntity) obj;
                for (FastJsonResponse.Field<?, ?> field : zzaHP.values()) {
                    if (zza(field)) {
                        if (organizationsEntity.zza(field) && zzb(field).equals(organizationsEntity.zzb(field))) {
                        }
                        return false;
                    } else if (organizationsEntity.zza(field)) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Organizations
        public String getDepartment() {
            return this.zzaJs;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Organizations
        public String getDescription() {
            return this.zzakM;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Organizations
        public String getEndDate() {
            return this.zzaIn;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Organizations
        public String getLocation() {
            return this.zzaJt;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Organizations
        public String getName() {
            return this.mName;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Organizations
        public String getStartDate() {
            return this.zzaID;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Organizations
        public String getTitle() {
            return this.zzadv;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Organizations
        public int getType() {
            return this.zzSq;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Organizations
        public boolean hasDepartment() {
            return this.zzaHQ.contains(2);
        }

        @Override // com.google.android.gms.plus.model.people.Person.Organizations
        public boolean hasDescription() {
            return this.zzaHQ.contains(3);
        }

        @Override // com.google.android.gms.plus.model.people.Person.Organizations
        public boolean hasEndDate() {
            return this.zzaHQ.contains(4);
        }

        @Override // com.google.android.gms.plus.model.people.Person.Organizations
        public boolean hasLocation() {
            return this.zzaHQ.contains(5);
        }

        @Override // com.google.android.gms.plus.model.people.Person.Organizations
        public boolean hasName() {
            return this.zzaHQ.contains(6);
        }

        @Override // com.google.android.gms.plus.model.people.Person.Organizations
        public boolean hasPrimary() {
            return this.zzaHQ.contains(7);
        }

        @Override // com.google.android.gms.plus.model.people.Person.Organizations
        public boolean hasStartDate() {
            return this.zzaHQ.contains(8);
        }

        @Override // com.google.android.gms.plus.model.people.Person.Organizations
        public boolean hasTitle() {
            return this.zzaHQ.contains(9);
        }

        @Override // com.google.android.gms.plus.model.people.Person.Organizations
        public boolean hasType() {
            return this.zzaHQ.contains(10);
        }

        public int hashCode() {
            int i = 0;
            Iterator<FastJsonResponse.Field<?, ?>> it = zzaHP.values().iterator();
            while (true) {
                int i2 = i;
                if (!it.hasNext()) {
                    return i2;
                }
                FastJsonResponse.Field<?, ?> next = it.next();
                if (zza(next)) {
                    i = zzb(next).hashCode() + i2 + next.zzot();
                } else {
                    i = i2;
                }
            }
        }

        @Override // com.google.android.gms.common.data.Freezable
        public boolean isDataValid() {
            return true;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Organizations
        public boolean isPrimary() {
            return this.zzaJu;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel out, int flags) {
            zzh zzhVar = CREATOR;
            zzh.zza(this, out, flags);
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        protected boolean zza(FastJsonResponse.Field field) {
            return this.zzaHQ.contains(Integer.valueOf(field.zzot()));
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        protected Object zzb(FastJsonResponse.Field field) {
            switch (field.zzot()) {
                case 2:
                    return this.zzaJs;
                case 3:
                    return this.zzakM;
                case 4:
                    return this.zzaIn;
                case 5:
                    return this.zzaJt;
                case 6:
                    return this.mName;
                case 7:
                    return Boolean.valueOf(this.zzaJu);
                case 8:
                    return this.zzaID;
                case 9:
                    return this.zzadv;
                case 10:
                    return Integer.valueOf(this.zzSq);
                default:
                    throw new IllegalStateException("Unknown safe parcelable id=" + field.zzot());
            }
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        /* renamed from: zzxF */
        public HashMap<String, FastJsonResponse.Field<?, ?>> zzom() {
            return zzaHP;
        }

        @Override // com.google.android.gms.common.data.Freezable
        /* renamed from: zzxQ */
        public OrganizationsEntity freeze() {
            return this;
        }
    }

    /* loaded from: classes.dex */
    public static final class PlacesLivedEntity extends FastSafeParcelableJsonResponse implements Person.PlacesLived {
        public static final zzi CREATOR = new zzi();
        private static final HashMap<String, FastJsonResponse.Field<?, ?>> zzaHP = new HashMap<>();
        String mValue;
        final int zzCY;
        final Set<Integer> zzaHQ;
        boolean zzaJu;

        static {
            zzaHP.put("primary", FastJsonResponse.Field.zzk("primary", 2));
            zzaHP.put("value", FastJsonResponse.Field.zzl("value", 3));
        }

        public PlacesLivedEntity() {
            this.zzCY = 1;
            this.zzaHQ = new HashSet();
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public PlacesLivedEntity(Set<Integer> indicatorSet, int versionCode, boolean primary, String value) {
            this.zzaHQ = indicatorSet;
            this.zzCY = versionCode;
            this.zzaJu = primary;
            this.mValue = value;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            zzi zziVar = CREATOR;
            return 0;
        }

        public boolean equals(Object obj) {
            if (obj instanceof PlacesLivedEntity) {
                if (this == obj) {
                    return true;
                }
                PlacesLivedEntity placesLivedEntity = (PlacesLivedEntity) obj;
                for (FastJsonResponse.Field<?, ?> field : zzaHP.values()) {
                    if (zza(field)) {
                        if (placesLivedEntity.zza(field) && zzb(field).equals(placesLivedEntity.zzb(field))) {
                        }
                        return false;
                    } else if (placesLivedEntity.zza(field)) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }

        @Override // com.google.android.gms.plus.model.people.Person.PlacesLived
        public String getValue() {
            return this.mValue;
        }

        @Override // com.google.android.gms.plus.model.people.Person.PlacesLived
        public boolean hasPrimary() {
            return this.zzaHQ.contains(2);
        }

        @Override // com.google.android.gms.plus.model.people.Person.PlacesLived
        public boolean hasValue() {
            return this.zzaHQ.contains(3);
        }

        public int hashCode() {
            int i = 0;
            Iterator<FastJsonResponse.Field<?, ?>> it = zzaHP.values().iterator();
            while (true) {
                int i2 = i;
                if (!it.hasNext()) {
                    return i2;
                }
                FastJsonResponse.Field<?, ?> next = it.next();
                if (zza(next)) {
                    i = zzb(next).hashCode() + i2 + next.zzot();
                } else {
                    i = i2;
                }
            }
        }

        @Override // com.google.android.gms.common.data.Freezable
        public boolean isDataValid() {
            return true;
        }

        @Override // com.google.android.gms.plus.model.people.Person.PlacesLived
        public boolean isPrimary() {
            return this.zzaJu;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel out, int flags) {
            zzi zziVar = CREATOR;
            zzi.zza(this, out, flags);
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        protected boolean zza(FastJsonResponse.Field field) {
            return this.zzaHQ.contains(Integer.valueOf(field.zzot()));
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        protected Object zzb(FastJsonResponse.Field field) {
            switch (field.zzot()) {
                case 2:
                    return Boolean.valueOf(this.zzaJu);
                case 3:
                    return this.mValue;
                default:
                    throw new IllegalStateException("Unknown safe parcelable id=" + field.zzot());
            }
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        /* renamed from: zzxF */
        public HashMap<String, FastJsonResponse.Field<?, ?>> zzom() {
            return zzaHP;
        }

        @Override // com.google.android.gms.common.data.Freezable
        /* renamed from: zzxR */
        public PlacesLivedEntity freeze() {
            return this;
        }
    }

    /* loaded from: classes.dex */
    public static final class UrlsEntity extends FastSafeParcelableJsonResponse implements Person.Urls {
        public static final zzj CREATOR = new zzj();
        private static final HashMap<String, FastJsonResponse.Field<?, ?>> zzaHP = new HashMap<>();
        String mValue;
        final int zzCY;
        int zzSq;
        String zzaEH;
        final Set<Integer> zzaHQ;
        private final int zzaJv;

        static {
            zzaHP.put(PlusShare.KEY_CALL_TO_ACTION_LABEL, FastJsonResponse.Field.zzl(PlusShare.KEY_CALL_TO_ACTION_LABEL, 5));
            zzaHP.put("type", FastJsonResponse.Field.zza("type", 6, new StringToIntConverter().zzh("home", 0).zzh("work", 1).zzh("blog", 2).zzh(Scopes.PROFILE, 3).zzh(FitnessActivities.OTHER, 4).zzh("otherProfile", 5).zzh("contributor", 6).zzh("website", 7), false));
            zzaHP.put("value", FastJsonResponse.Field.zzl("value", 4));
        }

        public UrlsEntity() {
            this.zzaJv = 4;
            this.zzCY = 1;
            this.zzaHQ = new HashSet();
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public UrlsEntity(Set<Integer> indicatorSet, int versionCode, String label, int type, String value, int type_DEPRECATED_FENACHO) {
            this.zzaJv = 4;
            this.zzaHQ = indicatorSet;
            this.zzCY = versionCode;
            this.zzaEH = label;
            this.zzSq = type;
            this.mValue = value;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            zzj zzjVar = CREATOR;
            return 0;
        }

        public boolean equals(Object obj) {
            if (obj instanceof UrlsEntity) {
                if (this == obj) {
                    return true;
                }
                UrlsEntity urlsEntity = (UrlsEntity) obj;
                for (FastJsonResponse.Field<?, ?> field : zzaHP.values()) {
                    if (zza(field)) {
                        if (urlsEntity.zza(field) && zzb(field).equals(urlsEntity.zzb(field))) {
                        }
                        return false;
                    } else if (urlsEntity.zza(field)) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Urls
        public String getLabel() {
            return this.zzaEH;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Urls
        public int getType() {
            return this.zzSq;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Urls
        public String getValue() {
            return this.mValue;
        }

        @Override // com.google.android.gms.plus.model.people.Person.Urls
        public boolean hasLabel() {
            return this.zzaHQ.contains(5);
        }

        @Override // com.google.android.gms.plus.model.people.Person.Urls
        public boolean hasType() {
            return this.zzaHQ.contains(6);
        }

        @Override // com.google.android.gms.plus.model.people.Person.Urls
        public boolean hasValue() {
            return this.zzaHQ.contains(4);
        }

        public int hashCode() {
            int i = 0;
            Iterator<FastJsonResponse.Field<?, ?>> it = zzaHP.values().iterator();
            while (true) {
                int i2 = i;
                if (!it.hasNext()) {
                    return i2;
                }
                FastJsonResponse.Field<?, ?> next = it.next();
                if (zza(next)) {
                    i = zzb(next).hashCode() + i2 + next.zzot();
                } else {
                    i = i2;
                }
            }
        }

        @Override // com.google.android.gms.common.data.Freezable
        public boolean isDataValid() {
            return true;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel out, int flags) {
            zzj zzjVar = CREATOR;
            zzj.zza(this, out, flags);
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        protected boolean zza(FastJsonResponse.Field field) {
            return this.zzaHQ.contains(Integer.valueOf(field.zzot()));
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        protected Object zzb(FastJsonResponse.Field field) {
            switch (field.zzot()) {
                case 4:
                    return this.mValue;
                case 5:
                    return this.zzaEH;
                case 6:
                    return Integer.valueOf(this.zzSq);
                default:
                    throw new IllegalStateException("Unknown safe parcelable id=" + field.zzot());
            }
        }

        @Override // com.google.android.gms.common.server.response.FastJsonResponse
        /* renamed from: zzxF */
        public HashMap<String, FastJsonResponse.Field<?, ?>> zzom() {
            return zzaHP;
        }

        @Deprecated
        public int zzxS() {
            return 4;
        }

        @Override // com.google.android.gms.common.data.Freezable
        /* renamed from: zzxT */
        public UrlsEntity freeze() {
            return this;
        }
    }

    /* loaded from: classes.dex */
    public static class zza {
        public static int zzdY(String str) {
            if (str.equals("person")) {
                return 0;
            }
            if (str.equals("page")) {
                return 1;
            }
            throw new IllegalArgumentException("Unknown objectType string: " + str);
        }
    }

    static {
        zzaHP.put("aboutMe", FastJsonResponse.Field.zzl("aboutMe", 2));
        zzaHP.put("ageRange", FastJsonResponse.Field.zza("ageRange", 3, AgeRangeEntity.class));
        zzaHP.put("birthday", FastJsonResponse.Field.zzl("birthday", 4));
        zzaHP.put("braggingRights", FastJsonResponse.Field.zzl("braggingRights", 5));
        zzaHP.put("circledByCount", FastJsonResponse.Field.zzi("circledByCount", 6));
        zzaHP.put("cover", FastJsonResponse.Field.zza("cover", 7, CoverEntity.class));
        zzaHP.put("currentLocation", FastJsonResponse.Field.zzl("currentLocation", 8));
        zzaHP.put("displayName", FastJsonResponse.Field.zzl("displayName", 9));
        zzaHP.put("gender", FastJsonResponse.Field.zza("gender", 12, new StringToIntConverter().zzh("male", 0).zzh("female", 1).zzh(FitnessActivities.OTHER, 2), false));
        zzaHP.put("id", FastJsonResponse.Field.zzl("id", 14));
        zzaHP.put("image", FastJsonResponse.Field.zza("image", 15, ImageEntity.class));
        zzaHP.put("isPlusUser", FastJsonResponse.Field.zzk("isPlusUser", 16));
        zzaHP.put("language", FastJsonResponse.Field.zzl("language", 18));
        zzaHP.put("name", FastJsonResponse.Field.zza("name", 19, NameEntity.class));
        zzaHP.put("nickname", FastJsonResponse.Field.zzl("nickname", 20));
        zzaHP.put("objectType", FastJsonResponse.Field.zza("objectType", 21, new StringToIntConverter().zzh("person", 0).zzh("page", 1), false));
        zzaHP.put("organizations", FastJsonResponse.Field.zzb("organizations", 22, OrganizationsEntity.class));
        zzaHP.put("placesLived", FastJsonResponse.Field.zzb("placesLived", 23, PlacesLivedEntity.class));
        zzaHP.put("plusOneCount", FastJsonResponse.Field.zzi("plusOneCount", 24));
        zzaHP.put("relationshipStatus", FastJsonResponse.Field.zza("relationshipStatus", 25, new StringToIntConverter().zzh("single", 0).zzh("in_a_relationship", 1).zzh("engaged", 2).zzh("married", 3).zzh("its_complicated", 4).zzh("open_relationship", 5).zzh("widowed", 6).zzh("in_domestic_partnership", 7).zzh("in_civil_union", 8), false));
        zzaHP.put("tagline", FastJsonResponse.Field.zzl("tagline", 26));
        zzaHP.put(PlusShare.KEY_CALL_TO_ACTION_URL, FastJsonResponse.Field.zzl(PlusShare.KEY_CALL_TO_ACTION_URL, 27));
        zzaHP.put("urls", FastJsonResponse.Field.zzb("urls", 28, UrlsEntity.class));
        zzaHP.put("verified", FastJsonResponse.Field.zzk("verified", 29));
    }

    public PersonEntity() {
        this.zzCY = 1;
        this.zzaHQ = new HashSet();
    }

    public PersonEntity(String displayName, String id, ImageEntity image, int objectType, String url) {
        this.zzCY = 1;
        this.zzaHQ = new HashSet();
        this.zzadI = displayName;
        this.zzaHQ.add(9);
        this.zzKI = id;
        this.zzaHQ.add(14);
        this.zzaIV = image;
        this.zzaHQ.add(15);
        this.zzaIZ = objectType;
        this.zzaHQ.add(21);
        this.zzF = url;
        this.zzaHQ.add(27);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public PersonEntity(Set<Integer> indicatorSet, int versionCode, String aboutMe, AgeRangeEntity ageRange, String birthday, String braggingRights, int circledByCount, CoverEntity cover, String currentLocation, String displayName, int gender, String id, ImageEntity image, boolean isPlusUser, String language, NameEntity name, String nickname, int objectType, List<OrganizationsEntity> organizations, List<PlacesLivedEntity> placesLived, int plusOneCount, int relationshipStatus, String tagline, String url, List<UrlsEntity> urls, boolean verified) {
        this.zzaHQ = indicatorSet;
        this.zzCY = versionCode;
        this.zzaIO = aboutMe;
        this.zzaIP = ageRange;
        this.zzaIQ = birthday;
        this.zzaIR = braggingRights;
        this.zzaIS = circledByCount;
        this.zzaIT = cover;
        this.zzaIU = currentLocation;
        this.zzadI = displayName;
        this.zzsC = gender;
        this.zzKI = id;
        this.zzaIV = image;
        this.zzaIW = isPlusUser;
        this.zzRA = language;
        this.zzaIX = name;
        this.zzaIY = nickname;
        this.zzaIZ = objectType;
        this.zzaJa = organizations;
        this.zzaJb = placesLived;
        this.zzaJc = plusOneCount;
        this.zzaJd = relationshipStatus;
        this.zzaJe = tagline;
        this.zzF = url;
        this.zzaJf = urls;
        this.zzaJg = verified;
    }

    public static PersonEntity zzp(byte[] bArr) {
        Parcel obtain = Parcel.obtain();
        obtain.unmarshall(bArr, 0, bArr.length);
        obtain.setDataPosition(0);
        PersonEntity createFromParcel = CREATOR.createFromParcel(obtain);
        obtain.recycle();
        return createFromParcel;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        com.google.android.gms.plus.internal.model.people.zza zzaVar = CREATOR;
        return 0;
    }

    public boolean equals(Object obj) {
        if (obj instanceof PersonEntity) {
            if (this == obj) {
                return true;
            }
            PersonEntity personEntity = (PersonEntity) obj;
            for (FastJsonResponse.Field<?, ?> field : zzaHP.values()) {
                if (zza(field)) {
                    if (personEntity.zza(field) && zzb(field).equals(personEntity.zzb(field))) {
                    }
                    return false;
                } else if (personEntity.zza(field)) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public String getAboutMe() {
        return this.zzaIO;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public Person.AgeRange getAgeRange() {
        return this.zzaIP;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public String getBirthday() {
        return this.zzaIQ;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public String getBraggingRights() {
        return this.zzaIR;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public int getCircledByCount() {
        return this.zzaIS;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public Person.Cover getCover() {
        return this.zzaIT;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public String getCurrentLocation() {
        return this.zzaIU;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public String getDisplayName() {
        return this.zzadI;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public int getGender() {
        return this.zzsC;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public String getId() {
        return this.zzKI;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public Person.Image getImage() {
        return this.zzaIV;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public String getLanguage() {
        return this.zzRA;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public Person.Name getName() {
        return this.zzaIX;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public String getNickname() {
        return this.zzaIY;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public int getObjectType() {
        return this.zzaIZ;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public List<Person.Organizations> getOrganizations() {
        return (ArrayList) this.zzaJa;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public List<Person.PlacesLived> getPlacesLived() {
        return (ArrayList) this.zzaJb;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public int getPlusOneCount() {
        return this.zzaJc;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public int getRelationshipStatus() {
        return this.zzaJd;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public String getTagline() {
        return this.zzaJe;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public String getUrl() {
        return this.zzF;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public List<Person.Urls> getUrls() {
        return (ArrayList) this.zzaJf;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasAboutMe() {
        return this.zzaHQ.contains(2);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasAgeRange() {
        return this.zzaHQ.contains(3);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasBirthday() {
        return this.zzaHQ.contains(4);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasBraggingRights() {
        return this.zzaHQ.contains(5);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasCircledByCount() {
        return this.zzaHQ.contains(6);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasCover() {
        return this.zzaHQ.contains(7);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasCurrentLocation() {
        return this.zzaHQ.contains(8);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasDisplayName() {
        return this.zzaHQ.contains(9);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasGender() {
        return this.zzaHQ.contains(12);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasId() {
        return this.zzaHQ.contains(14);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasImage() {
        return this.zzaHQ.contains(15);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasIsPlusUser() {
        return this.zzaHQ.contains(16);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasLanguage() {
        return this.zzaHQ.contains(18);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasName() {
        return this.zzaHQ.contains(19);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasNickname() {
        return this.zzaHQ.contains(20);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasObjectType() {
        return this.zzaHQ.contains(21);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasOrganizations() {
        return this.zzaHQ.contains(22);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasPlacesLived() {
        return this.zzaHQ.contains(23);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasPlusOneCount() {
        return this.zzaHQ.contains(24);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasRelationshipStatus() {
        return this.zzaHQ.contains(25);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasTagline() {
        return this.zzaHQ.contains(26);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasUrl() {
        return this.zzaHQ.contains(27);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasUrls() {
        return this.zzaHQ.contains(28);
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean hasVerified() {
        return this.zzaHQ.contains(29);
    }

    public int hashCode() {
        int i = 0;
        Iterator<FastJsonResponse.Field<?, ?>> it = zzaHP.values().iterator();
        while (true) {
            int i2 = i;
            if (!it.hasNext()) {
                return i2;
            }
            FastJsonResponse.Field<?, ?> next = it.next();
            if (zza(next)) {
                i = zzb(next).hashCode() + i2 + next.zzot();
            } else {
                i = i2;
            }
        }
    }

    @Override // com.google.android.gms.common.data.Freezable
    public boolean isDataValid() {
        return true;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean isPlusUser() {
        return this.zzaIW;
    }

    @Override // com.google.android.gms.plus.model.people.Person
    public boolean isVerified() {
        return this.zzaJg;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        com.google.android.gms.plus.internal.model.people.zza zzaVar = CREATOR;
        com.google.android.gms.plus.internal.model.people.zza.zza(this, out, flags);
    }

    @Override // com.google.android.gms.common.server.response.FastJsonResponse
    protected boolean zza(FastJsonResponse.Field field) {
        return this.zzaHQ.contains(Integer.valueOf(field.zzot()));
    }

    @Override // com.google.android.gms.common.server.response.FastJsonResponse
    protected Object zzb(FastJsonResponse.Field field) {
        switch (field.zzot()) {
            case 2:
                return this.zzaIO;
            case 3:
                return this.zzaIP;
            case 4:
                return this.zzaIQ;
            case 5:
                return this.zzaIR;
            case 6:
                return Integer.valueOf(this.zzaIS);
            case 7:
                return this.zzaIT;
            case 8:
                return this.zzaIU;
            case 9:
                return this.zzadI;
            case 10:
            case 11:
            case 13:
            case 17:
            default:
                throw new IllegalStateException("Unknown safe parcelable id=" + field.zzot());
            case 12:
                return Integer.valueOf(this.zzsC);
            case 14:
                return this.zzKI;
            case 15:
                return this.zzaIV;
            case 16:
                return Boolean.valueOf(this.zzaIW);
            case 18:
                return this.zzRA;
            case 19:
                return this.zzaIX;
            case 20:
                return this.zzaIY;
            case 21:
                return Integer.valueOf(this.zzaIZ);
            case 22:
                return this.zzaJa;
            case 23:
                return this.zzaJb;
            case 24:
                return Integer.valueOf(this.zzaJc);
            case 25:
                return Integer.valueOf(this.zzaJd);
            case 26:
                return this.zzaJe;
            case 27:
                return this.zzF;
            case 28:
                return this.zzaJf;
            case 29:
                return Boolean.valueOf(this.zzaJg);
        }
    }

    @Override // com.google.android.gms.common.server.response.FastJsonResponse
    /* renamed from: zzxF */
    public HashMap<String, FastJsonResponse.Field<?, ?>> zzom() {
        return zzaHP;
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzxJ */
    public PersonEntity freeze() {
        return this;
    }
}
