package com.google.android.gms.games.appcontent;

import android.os.Bundle;
import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
/* loaded from: classes.dex */
public final class AppContentConditionEntity implements SafeParcelable, AppContentCondition {
    public static final AppContentConditionEntityCreator CREATOR = new AppContentConditionEntityCreator();
    private final int zzCY;
    private final String zzaoA;
    private final String zzaoB;
    private final Bundle zzaoC;
    private final String zzaoz;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AppContentConditionEntity(int versionCode, String defaultValue, String expectedValue, String predicate, Bundle predicateParameters) {
        this.zzCY = versionCode;
        this.zzaoz = defaultValue;
        this.zzaoA = expectedValue;
        this.zzaoB = predicate;
        this.zzaoC = predicateParameters;
    }

    public AppContentConditionEntity(AppContentCondition condition) {
        this.zzCY = 1;
        this.zzaoz = condition.zzse();
        this.zzaoA = condition.zzsf();
        this.zzaoB = condition.zzsg();
        this.zzaoC = condition.zzsh();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int zza(AppContentCondition appContentCondition) {
        return zzt.hashCode(appContentCondition.zzse(), appContentCondition.zzsf(), appContentCondition.zzsg(), appContentCondition.zzsh());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean zza(AppContentCondition appContentCondition, Object obj) {
        if (obj instanceof AppContentCondition) {
            if (appContentCondition != obj) {
                AppContentCondition appContentCondition2 = (AppContentCondition) obj;
                return zzt.equal(appContentCondition2.zzse(), appContentCondition.zzse()) && zzt.equal(appContentCondition2.zzsf(), appContentCondition.zzsf()) && zzt.equal(appContentCondition2.zzsg(), appContentCondition.zzsg()) && zzt.equal(appContentCondition2.zzsh(), appContentCondition.zzsh());
            }
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String zzb(AppContentCondition appContentCondition) {
        return zzt.zzt(appContentCondition).zzg("DefaultValue", appContentCondition.zzse()).zzg("ExpectedValue", appContentCondition.zzsf()).zzg("Predicate", appContentCondition.zzsg()).zzg("PredicateParameters", appContentCondition.zzsh()).toString();
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object obj) {
        return zza(this, obj);
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
        AppContentConditionEntityCreator.zza(this, out, flags);
    }

    @Override // com.google.android.gms.games.appcontent.AppContentCondition
    public String zzse() {
        return this.zzaoz;
    }

    @Override // com.google.android.gms.games.appcontent.AppContentCondition
    public String zzsf() {
        return this.zzaoA;
    }

    @Override // com.google.android.gms.games.appcontent.AppContentCondition
    public String zzsg() {
        return this.zzaoB;
    }

    @Override // com.google.android.gms.games.appcontent.AppContentCondition
    public Bundle zzsh() {
        return this.zzaoC;
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzsi */
    public AppContentCondition freeze() {
        return this;
    }
}
