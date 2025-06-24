package com.google.android.gms.common.images;

import android.net.Uri;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.plus.PlusShare;
import org.json.JSONException;
import org.json.JSONObject;
/* loaded from: classes.dex */
public final class WebImage implements SafeParcelable {
    public static final Parcelable.Creator<WebImage> CREATOR = new zzb();
    private final int zzCY;
    private final Uri zzZn;
    private final int zznM;
    private final int zznN;

    /* JADX INFO: Access modifiers changed from: package-private */
    public WebImage(int versionCode, Uri url, int width, int height) {
        this.zzCY = versionCode;
        this.zzZn = url;
        this.zznM = width;
        this.zznN = height;
    }

    public WebImage(Uri url) throws IllegalArgumentException {
        this(url, 0, 0);
    }

    public WebImage(Uri url, int width, int height) throws IllegalArgumentException {
        this(1, url, width, height);
        if (url == null) {
            throw new IllegalArgumentException("url cannot be null");
        }
        if (width < 0 || height < 0) {
            throw new IllegalArgumentException("width and height must not be negative");
        }
    }

    public WebImage(JSONObject json) throws IllegalArgumentException {
        this(zzi(json), json.optInt("width", 0), json.optInt("height", 0));
    }

    private static Uri zzi(JSONObject jSONObject) {
        if (jSONObject.has(PlusShare.KEY_CALL_TO_ACTION_URL)) {
            try {
                return Uri.parse(jSONObject.getString(PlusShare.KEY_CALL_TO_ACTION_URL));
            } catch (JSONException e) {
                return null;
            }
        }
        return null;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other == null || !(other instanceof WebImage)) {
            return false;
        }
        WebImage webImage = (WebImage) other;
        return zzt.equal(this.zzZn, webImage.zzZn) && this.zznM == webImage.zznM && this.zznN == webImage.zznN;
    }

    public int getHeight() {
        return this.zznN;
    }

    public Uri getUrl() {
        return this.zzZn;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int getWidth() {
        return this.zznM;
    }

    public int hashCode() {
        return zzt.hashCode(this.zzZn, Integer.valueOf(this.zznM), Integer.valueOf(this.zznN));
    }

    public JSONObject toJson() {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put(PlusShare.KEY_CALL_TO_ACTION_URL, this.zzZn.toString());
            jSONObject.put("width", this.zznM);
            jSONObject.put("height", this.zznN);
        } catch (JSONException e) {
        }
        return jSONObject;
    }

    public String toString() {
        return String.format("Image %dx%d %s", Integer.valueOf(this.zznM), Integer.valueOf(this.zznN), this.zzZn.toString());
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzb.zza(this, out, flags);
    }
}
