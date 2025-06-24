package com.google.android.gms.ads.internal.client;

import android.content.Context;
import android.location.Location;
import android.os.Bundle;
import com.google.ads.mediation.admob.AdMobAdapter;
import com.google.android.gms.ads.internal.reward.client.RewardedVideoAdRequestParcel;
import com.google.android.gms.ads.search.SearchAdRequest;
import com.google.android.gms.internal.zzgd;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
@zzgd
/* loaded from: classes.dex */
public class zzg {
    public static final zzg zzsl = new zzg();

    protected zzg() {
    }

    public static zzg zzcw() {
        return zzsl;
    }

    public AdRequestParcel zza(Context context, zzx zzxVar) {
        Date birthday = zzxVar.getBirthday();
        long time = birthday != null ? birthday.getTime() : -1L;
        String contentUrl = zzxVar.getContentUrl();
        int gender = zzxVar.getGender();
        Set<String> keywords = zzxVar.getKeywords();
        List unmodifiableList = !keywords.isEmpty() ? Collections.unmodifiableList(new ArrayList(keywords)) : null;
        boolean isTestDevice = zzxVar.isTestDevice(context);
        int zzcL = zzxVar.zzcL();
        Location location = zzxVar.getLocation();
        Bundle networkExtrasBundle = zzxVar.getNetworkExtrasBundle(AdMobAdapter.class);
        boolean manualImpressionsEnabled = zzxVar.getManualImpressionsEnabled();
        String publisherProvidedId = zzxVar.getPublisherProvidedId();
        SearchAdRequest zzcI = zzxVar.zzcI();
        return new AdRequestParcel(5, time, networkExtrasBundle, gender, unmodifiableList, isTestDevice, zzcL, manualImpressionsEnabled, publisherProvidedId, zzcI != null ? new SearchAdRequestParcel(zzcI) : null, location, contentUrl, zzxVar.zzcK(), zzxVar.getCustomTargeting(), Collections.unmodifiableList(new ArrayList(zzxVar.zzcM())), zzxVar.zzcH());
    }

    public RewardedVideoAdRequestParcel zza(Context context, zzx zzxVar, String str) {
        return new RewardedVideoAdRequestParcel(zza(context, zzxVar), str);
    }
}
