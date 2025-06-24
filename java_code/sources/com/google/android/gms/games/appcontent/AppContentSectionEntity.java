package com.google.android.gms.games.appcontent;

import android.os.Bundle;
import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import java.util.ArrayList;
import java.util.List;
/* loaded from: classes.dex */
public final class AppContentSectionEntity implements SafeParcelable, AppContentSection {
    public static final AppContentSectionEntityCreator CREATOR = new AppContentSectionEntityCreator();
    private final ArrayList<AppContentActionEntity> mActions;
    private final Bundle mExtras;
    private final int zzCY;
    private final String zzEl;
    private final String zzKI;
    private final String zzadv;
    private final ArrayList<AppContentCardEntity> zzaoE;
    private final String zzaoF;
    private final String zzaom;
    private final ArrayList<AppContentAnnotationEntity> zzaov;
    private final String zzaox;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AppContentSectionEntity(int versionCode, ArrayList<AppContentActionEntity> actions, ArrayList<AppContentCardEntity> cards, String contentDescription, Bundle extras, String subtitle, String title, String type, String id, String cardType, ArrayList<AppContentAnnotationEntity> annotations) {
        this.zzCY = versionCode;
        this.mActions = actions;
        this.zzaov = annotations;
        this.zzaoE = cards;
        this.zzaoF = cardType;
        this.zzaom = contentDescription;
        this.mExtras = extras;
        this.zzKI = id;
        this.zzaox = subtitle;
        this.zzadv = title;
        this.zzEl = type;
    }

    public AppContentSectionEntity(AppContentSection section) {
        this.zzCY = 5;
        this.zzaoF = section.zzsk();
        this.zzaom = section.zzrP();
        this.mExtras = section.getExtras();
        this.zzKI = section.getId();
        this.zzaox = section.zzsb();
        this.zzadv = section.getTitle();
        this.zzEl = section.getType();
        List<AppContentAction> actions = section.getActions();
        int size = actions.size();
        this.mActions = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            this.mActions.add((AppContentActionEntity) actions.get(i).freeze());
        }
        List<AppContentCard> zzsj = section.zzsj();
        int size2 = zzsj.size();
        this.zzaoE = new ArrayList<>(size2);
        for (int i2 = 0; i2 < size2; i2++) {
            this.zzaoE.add((AppContentCardEntity) zzsj.get(i2).freeze());
        }
        List<AppContentAnnotation> zzrZ = section.zzrZ();
        int size3 = zzrZ.size();
        this.zzaov = new ArrayList<>(size3);
        for (int i3 = 0; i3 < size3; i3++) {
            this.zzaov.add((AppContentAnnotationEntity) zzrZ.get(i3).freeze());
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int zza(AppContentSection appContentSection) {
        return zzt.hashCode(appContentSection.getActions(), appContentSection.zzrZ(), appContentSection.zzsj(), appContentSection.zzsk(), appContentSection.zzrP(), appContentSection.getExtras(), appContentSection.getId(), appContentSection.zzsb(), appContentSection.getTitle(), appContentSection.getType());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean zza(AppContentSection appContentSection, Object obj) {
        if (obj instanceof AppContentSection) {
            if (appContentSection != obj) {
                AppContentSection appContentSection2 = (AppContentSection) obj;
                return zzt.equal(appContentSection2.getActions(), appContentSection.getActions()) && zzt.equal(appContentSection2.zzrZ(), appContentSection.zzrZ()) && zzt.equal(appContentSection2.zzsj(), appContentSection.zzsj()) && zzt.equal(appContentSection2.zzsk(), appContentSection.zzsk()) && zzt.equal(appContentSection2.zzrP(), appContentSection.zzrP()) && zzt.equal(appContentSection2.getExtras(), appContentSection.getExtras()) && zzt.equal(appContentSection2.getId(), appContentSection.getId()) && zzt.equal(appContentSection2.zzsb(), appContentSection.zzsb()) && zzt.equal(appContentSection2.getTitle(), appContentSection.getTitle()) && zzt.equal(appContentSection2.getType(), appContentSection.getType());
            }
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String zzb(AppContentSection appContentSection) {
        return zzt.zzt(appContentSection).zzg("Actions", appContentSection.getActions()).zzg("Annotations", appContentSection.zzrZ()).zzg("Cards", appContentSection.zzsj()).zzg("CardType", appContentSection.zzsk()).zzg("ContentDescription", appContentSection.zzrP()).zzg("Extras", appContentSection.getExtras()).zzg("Id", appContentSection.getId()).zzg("Subtitle", appContentSection.zzsb()).zzg("Title", appContentSection.getTitle()).zzg("Type", appContentSection.getType()).toString();
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object obj) {
        return zza(this, obj);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    public List<AppContentAction> getActions() {
        return new ArrayList(this.mActions);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    public Bundle getExtras() {
        return this.mExtras;
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    public String getId() {
        return this.zzKI;
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    public String getTitle() {
        return this.zzadv;
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    public String getType() {
        return this.zzEl;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return zza(this);
    }

    @Override // com.google.android.gms.common.data.Freezable
    public boolean isDataValid() {
        return true;
    }

    public String toString() {
        return zzb(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        AppContentSectionEntityCreator.zza(this, out, flags);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    public String zzrP() {
        return this.zzaom;
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    public List<AppContentAnnotation> zzrZ() {
        return new ArrayList(this.zzaov);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    public String zzsb() {
        return this.zzaox;
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    public List<AppContentCard> zzsj() {
        return new ArrayList(this.zzaoE);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentSection
    public String zzsk() {
        return this.zzaoF;
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzsl */
    public AppContentSection freeze() {
        return this;
    }
}
