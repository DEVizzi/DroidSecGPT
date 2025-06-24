package com.google.android.gms.drive.metadata.internal;

import android.content.Context;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.data.BitmapTeleporter;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.drive.internal.zzx;
import com.google.android.gms.drive.metadata.MetadataField;
import com.google.android.gms.internal.zzlo;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
/* loaded from: classes.dex */
public final class MetadataBundle implements SafeParcelable {
    public static final Parcelable.Creator<MetadataBundle> CREATOR = new zzh();
    final int zzCY;
    final Bundle zzagI;

    /* JADX INFO: Access modifiers changed from: package-private */
    public MetadataBundle(int versionCode, Bundle valueBundle) {
        this.zzCY = versionCode;
        this.zzagI = (Bundle) zzu.zzu(valueBundle);
        this.zzagI.setClassLoader(getClass().getClassLoader());
        ArrayList<String> arrayList = new ArrayList();
        for (String str : this.zzagI.keySet()) {
            if (zze.zzcw(str) == null) {
                arrayList.add(str);
                zzx.zzu("MetadataBundle", "Ignored unknown metadata field in bundle: " + str);
            }
        }
        for (String str2 : arrayList) {
            this.zzagI.remove(str2);
        }
    }

    private MetadataBundle(Bundle valueBundle) {
        this(1, valueBundle);
    }

    public static <T> MetadataBundle zza(MetadataField<T> metadataField, T t) {
        MetadataBundle zzpX = zzpX();
        zzpX.zzb(metadataField, t);
        return zzpX;
    }

    public static MetadataBundle zza(MetadataBundle metadataBundle) {
        return new MetadataBundle(new Bundle(metadataBundle.zzagI));
    }

    public static MetadataBundle zzpX() {
        return new MetadataBundle(new Bundle());
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof MetadataBundle) {
            MetadataBundle metadataBundle = (MetadataBundle) obj;
            Set<String> keySet = this.zzagI.keySet();
            if (keySet.equals(metadataBundle.zzagI.keySet())) {
                for (String str : keySet) {
                    if (!zzt.equal(this.zzagI.get(str), metadataBundle.zzagI.get(str))) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }
        return false;
    }

    public int hashCode() {
        int i = 1;
        Iterator<String> it = this.zzagI.keySet().iterator();
        while (true) {
            int i2 = i;
            if (!it.hasNext()) {
                return i2;
            }
            i = this.zzagI.get(it.next()).hashCode() + (i2 * 31);
        }
    }

    public void setContext(Context context) {
        BitmapTeleporter bitmapTeleporter = (BitmapTeleporter) zza(zzlo.zzaho);
        if (bitmapTeleporter != null) {
            bitmapTeleporter.zzc(context.getCacheDir());
        }
    }

    public String toString() {
        return "MetadataBundle [values=" + this.zzagI + "]";
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzh.zza(this, dest, flags);
    }

    public <T> T zza(MetadataField<T> metadataField) {
        return metadataField.zzi(this.zzagI);
    }

    public <T> void zzb(MetadataField<T> metadataField, T t) {
        if (zze.zzcw(metadataField.getName()) == null) {
            throw new IllegalArgumentException("Unregistered field: " + metadataField.getName());
        }
        metadataField.zza(t, this.zzagI);
    }

    public boolean zzc(MetadataField<?> metadataField) {
        return this.zzagI.containsKey(metadataField.getName());
    }

    public Set<MetadataField<?>> zzpY() {
        HashSet hashSet = new HashSet();
        for (String str : this.zzagI.keySet()) {
            hashSet.add(zze.zzcw(str));
        }
        return hashSet;
    }
}
