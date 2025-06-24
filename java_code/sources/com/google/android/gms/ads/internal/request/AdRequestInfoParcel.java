package com.google.android.gms.ads.internal.request;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.os.Bundle;
import android.os.Messenger;
import android.os.Parcel;
import com.google.android.gms.ads.internal.client.AdRequestParcel;
import com.google.android.gms.ads.internal.client.AdSizeParcel;
import com.google.android.gms.ads.internal.formats.NativeAdOptionsParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.internal.zzgd;
import java.util.Collections;
import java.util.List;
@zzgd
/* loaded from: classes.dex */
public final class AdRequestInfoParcel implements SafeParcelable {
    public static final zzf CREATOR = new zzf();
    public final ApplicationInfo applicationInfo;
    public final int versionCode;
    public final boolean zzCA;
    public final int zzCB;
    public final String zzCC;
    public final long zzCD;
    public final String zzCE;
    public final List<String> zzCF;
    public final List<String> zzCG;
    public final Bundle zzCl;
    public final AdRequestParcel zzCm;
    public final PackageInfo zzCn;
    public final String zzCo;
    public final String zzCp;
    public final String zzCq;
    public final Bundle zzCr;
    public final int zzCs;
    public final Bundle zzCt;
    public final boolean zzCu;
    public final Messenger zzCv;
    public final int zzCw;
    public final int zzCx;
    public final float zzCy;
    public final String zzCz;
    public final String zzpF;
    public final String zzpG;
    public final VersionInfoParcel zzpJ;
    public final AdSizeParcel zzpN;
    public final NativeAdOptionsParcel zzqb;
    public final List<String> zzqd;

    @zzgd
    /* loaded from: classes.dex */
    public static final class zza {
        public final ApplicationInfo applicationInfo;
        public final boolean zzCA;
        public final int zzCB;
        public final long zzCD;
        public final String zzCE;
        public final List<String> zzCF;
        public final List<String> zzCG;
        public final Bundle zzCl;
        public final AdRequestParcel zzCm;
        public final PackageInfo zzCn;
        public final String zzCp;
        public final String zzCq;
        public final Bundle zzCr;
        public final int zzCs;
        public final Bundle zzCt;
        public final boolean zzCu;
        public final Messenger zzCv;
        public final int zzCw;
        public final int zzCx;
        public final float zzCy;
        public final String zzCz;
        public final String zzpF;
        public final String zzpG;
        public final VersionInfoParcel zzpJ;
        public final AdSizeParcel zzpN;
        public final NativeAdOptionsParcel zzqb;
        public final List<String> zzqd;

        public zza(Bundle bundle, AdRequestParcel adRequestParcel, AdSizeParcel adSizeParcel, String str, ApplicationInfo applicationInfo, PackageInfo packageInfo, String str2, String str3, VersionInfoParcel versionInfoParcel, Bundle bundle2, List<String> list, List<String> list2, Bundle bundle3, boolean z, Messenger messenger, int i, int i2, float f, String str4, boolean z2, int i3, long j, String str5, List<String> list3, String str6, NativeAdOptionsParcel nativeAdOptionsParcel) {
            this.zzCl = bundle;
            this.zzCm = adRequestParcel;
            this.zzpN = adSizeParcel;
            this.zzpG = str;
            this.applicationInfo = applicationInfo;
            this.zzCn = packageInfo;
            this.zzCp = str2;
            this.zzCq = str3;
            this.zzpJ = versionInfoParcel;
            this.zzCr = bundle2;
            this.zzCu = z;
            this.zzCv = messenger;
            this.zzCw = i;
            this.zzCx = i2;
            this.zzCy = f;
            if (list == null || list.size() <= 0) {
                this.zzCs = 0;
                this.zzqd = null;
                this.zzCG = null;
            } else {
                this.zzCs = 3;
                this.zzqd = list;
                this.zzCG = list2;
            }
            this.zzCt = bundle3;
            this.zzCz = str4;
            this.zzCA = z2;
            this.zzCB = i3;
            this.zzCD = j;
            this.zzCE = str5;
            this.zzCF = list3;
            this.zzpF = str6;
            this.zzqb = nativeAdOptionsParcel;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public AdRequestInfoParcel(int versionCode, Bundle adPositionBundle, AdRequestParcel adRequest, AdSizeParcel adSize, String adUnitId, ApplicationInfo applicationInfo, PackageInfo packageInfo, String querySpamSignals, String sequenceNumber, String sessionId, VersionInfoParcel versionInfo, Bundle stats, int nativeVersion, List<String> nativeTemplates, Bundle contentInfo, boolean useHTTPS, Messenger prefetchMessenger, int screenWidth, int screenHeight, float screenDensity, String viewHierarchy, boolean isAnalyticsInitialized, int screenId, String analyticsClientId, long correlationId, String requestId, List<String> experimentIds, String slotId, NativeAdOptionsParcel nativeAdOptions, List<String> nativeCustomTemplateIds) {
        this.versionCode = versionCode;
        this.zzCl = adPositionBundle;
        this.zzCm = adRequest;
        this.zzpN = adSize;
        this.zzpG = adUnitId;
        this.applicationInfo = applicationInfo;
        this.zzCn = packageInfo;
        this.zzCo = querySpamSignals;
        this.zzCp = sequenceNumber;
        this.zzCq = sessionId;
        this.zzpJ = versionInfo;
        this.zzCr = stats;
        this.zzCs = nativeVersion;
        this.zzqd = nativeTemplates;
        this.zzCG = nativeCustomTemplateIds == null ? Collections.emptyList() : Collections.unmodifiableList(nativeCustomTemplateIds);
        this.zzCt = contentInfo;
        this.zzCu = useHTTPS;
        this.zzCv = prefetchMessenger;
        this.zzCw = screenWidth;
        this.zzCx = screenHeight;
        this.zzCy = screenDensity;
        this.zzCz = viewHierarchy;
        this.zzCA = isAnalyticsInitialized;
        this.zzCB = screenId;
        this.zzCC = analyticsClientId;
        this.zzCD = correlationId;
        this.zzCE = requestId;
        this.zzCF = experimentIds == null ? Collections.emptyList() : Collections.unmodifiableList(experimentIds);
        this.zzpF = slotId;
        this.zzqb = nativeAdOptions;
    }

    public AdRequestInfoParcel(Bundle adPositionBundle, AdRequestParcel adRequest, AdSizeParcel adSize, String adUnitId, ApplicationInfo applicationInfo, PackageInfo packageInfo, String querySpamSignals, String sequenceNumber, String sessionId, VersionInfoParcel versionInfo, Bundle stats, int nativeVersion, List<String> nativeTemplates, List<String> nativeCustomTemplateIds, Bundle contentInfo, boolean useHTTPS, Messenger prefetchMessenger, int screenWidth, int screenHeight, float screenDensity, String viewHierarchy, boolean isAnalyticsInitialized, int screenId, String analyticsClientId, long correlationId, String requestId, List<String> experimentIds, String slotId, NativeAdOptionsParcel nativeAdOptionsParcel) {
        this(10, adPositionBundle, adRequest, adSize, adUnitId, applicationInfo, packageInfo, querySpamSignals, sequenceNumber, sessionId, versionInfo, stats, nativeVersion, nativeTemplates, contentInfo, useHTTPS, prefetchMessenger, screenWidth, screenHeight, screenDensity, viewHierarchy, isAnalyticsInitialized, screenId, analyticsClientId, correlationId, requestId, experimentIds, slotId, nativeAdOptionsParcel, nativeCustomTemplateIds);
    }

    public AdRequestInfoParcel(zza partialAdRequestInfo, String querySpamSignals, String analyticsClientId) {
        this(partialAdRequestInfo.zzCl, partialAdRequestInfo.zzCm, partialAdRequestInfo.zzpN, partialAdRequestInfo.zzpG, partialAdRequestInfo.applicationInfo, partialAdRequestInfo.zzCn, querySpamSignals, partialAdRequestInfo.zzCp, partialAdRequestInfo.zzCq, partialAdRequestInfo.zzpJ, partialAdRequestInfo.zzCr, partialAdRequestInfo.zzCs, partialAdRequestInfo.zzqd, partialAdRequestInfo.zzCG, partialAdRequestInfo.zzCt, partialAdRequestInfo.zzCu, partialAdRequestInfo.zzCv, partialAdRequestInfo.zzCw, partialAdRequestInfo.zzCx, partialAdRequestInfo.zzCy, partialAdRequestInfo.zzCz, partialAdRequestInfo.zzCA, partialAdRequestInfo.zzCB, analyticsClientId, partialAdRequestInfo.zzCD, partialAdRequestInfo.zzCE, partialAdRequestInfo.zzCF, partialAdRequestInfo.zzpF, partialAdRequestInfo.zzqb);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzf.zza(this, out, flags);
    }
}
