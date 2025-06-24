package com.google.android.gms.ads.internal.client;

import android.os.Parcel;
import com.google.android.gms.ads.search.SearchAdRequest;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.internal.zzgd;
@zzgd
/* loaded from: classes.dex */
public final class SearchAdRequestParcel implements SafeParcelable {
    public static final zzae CREATOR = new zzae();
    public final int backgroundColor;
    public final int versionCode;
    public final int zzth;
    public final int zzti;
    public final int zztj;
    public final int zztk;
    public final int zztl;
    public final int zztm;
    public final int zztn;
    public final String zzto;
    public final int zztp;
    public final String zztq;
    public final int zztr;
    public final int zzts;
    public final String zztt;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SearchAdRequestParcel(int versionCode, int anchorTextColor, int backgroundColor, int backgroundGradientBottom, int backgroundGradientTop, int borderColor, int borderThickness, int borderType, int callButtonColor, String channels, int descriptionTextColor, String fontFace, int headerTextColor, int headerTextSize, String query) {
        this.versionCode = versionCode;
        this.zzth = anchorTextColor;
        this.backgroundColor = backgroundColor;
        this.zzti = backgroundGradientBottom;
        this.zztj = backgroundGradientTop;
        this.zztk = borderColor;
        this.zztl = borderThickness;
        this.zztm = borderType;
        this.zztn = callButtonColor;
        this.zzto = channels;
        this.zztp = descriptionTextColor;
        this.zztq = fontFace;
        this.zztr = headerTextColor;
        this.zzts = headerTextSize;
        this.zztt = query;
    }

    public SearchAdRequestParcel(SearchAdRequest searchAdRequest) {
        this.versionCode = 1;
        this.zzth = searchAdRequest.getAnchorTextColor();
        this.backgroundColor = searchAdRequest.getBackgroundColor();
        this.zzti = searchAdRequest.getBackgroundGradientBottom();
        this.zztj = searchAdRequest.getBackgroundGradientTop();
        this.zztk = searchAdRequest.getBorderColor();
        this.zztl = searchAdRequest.getBorderThickness();
        this.zztm = searchAdRequest.getBorderType();
        this.zztn = searchAdRequest.getCallButtonColor();
        this.zzto = searchAdRequest.getCustomChannels();
        this.zztp = searchAdRequest.getDescriptionTextColor();
        this.zztq = searchAdRequest.getFontFace();
        this.zztr = searchAdRequest.getHeaderTextColor();
        this.zzts = searchAdRequest.getHeaderTextSize();
        this.zztt = searchAdRequest.getQuery();
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzae.zza(this, out, flags);
    }
}
