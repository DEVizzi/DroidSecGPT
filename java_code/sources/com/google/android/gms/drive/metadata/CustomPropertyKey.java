package com.google.android.gms.drive.metadata;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import java.util.regex.Pattern;
import org.json.JSONException;
import org.json.JSONObject;
/* loaded from: classes.dex */
public class CustomPropertyKey implements SafeParcelable {
    public static final int PRIVATE = 1;
    public static final int PUBLIC = 0;
    final int mVisibility;
    final int zzCY;
    final String zztw;
    public static final Parcelable.Creator<CustomPropertyKey> CREATOR = new zzc();
    private static final Pattern zzagC = Pattern.compile("[\\w.!@$%^&*()/-]+");

    /* JADX INFO: Access modifiers changed from: package-private */
    public CustomPropertyKey(int versionCode, String key, int visibility) {
        boolean z = true;
        zzu.zzb(key, "key");
        zzu.zzb(zzagC.matcher(key).matches(), "key name characters must be alphanumeric or one of .!@$%^&*()-_/");
        if (visibility != 0 && visibility != 1) {
            z = false;
        }
        zzu.zzb(z, "visibility must be either PUBLIC or PRIVATE");
        this.zzCY = versionCode;
        this.zztw = key;
        this.mVisibility = visibility;
    }

    public CustomPropertyKey(String key, int visibility) {
        this(1, key, visibility);
    }

    public static CustomPropertyKey fromJson(JSONObject jsonObject) throws JSONException {
        return new CustomPropertyKey(jsonObject.getString("key"), jsonObject.getInt("visibility"));
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object obj) {
        boolean z = true;
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (obj instanceof CustomPropertyKey) {
            CustomPropertyKey customPropertyKey = (CustomPropertyKey) obj;
            if (!customPropertyKey.getKey().equals(this.zztw) || customPropertyKey.getVisibility() != this.mVisibility) {
                z = false;
            }
            return z;
        }
        return false;
    }

    public String getKey() {
        return this.zztw;
    }

    public int getVisibility() {
        return this.mVisibility;
    }

    public int hashCode() {
        return (this.zztw + this.mVisibility).hashCode();
    }

    public JSONObject toJson() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("key", getKey());
        jSONObject.put("visibility", getVisibility());
        return jSONObject;
    }

    public String toString() {
        return "CustomPropertyKey(" + this.zztw + "," + this.mVisibility + ")";
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzc.zza(this, dest, flags);
    }
}
