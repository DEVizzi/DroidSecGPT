package com.google.android.gms.common.server.converter;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.server.response.FastJsonResponse;
/* loaded from: classes.dex */
public class ConverterWrapper implements SafeParcelable {
    public static final zza CREATOR = new zza();
    private final int zzCY;
    private final StringToIntConverter zzabA;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ConverterWrapper(int versionCode, StringToIntConverter stringToIntConverter) {
        this.zzCY = versionCode;
        this.zzabA = stringToIntConverter;
    }

    private ConverterWrapper(StringToIntConverter stringToIntConverter) {
        this.zzCY = 1;
        this.zzabA = stringToIntConverter;
    }

    public static ConverterWrapper zza(FastJsonResponse.zza<?, ?> zzaVar) {
        if (zzaVar instanceof StringToIntConverter) {
            return new ConverterWrapper((StringToIntConverter) zzaVar);
        }
        throw new IllegalArgumentException("Unsupported safe parcelable field converter class.");
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zza zzaVar = CREATOR;
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zza zzaVar = CREATOR;
        zza.zza(this, out, flags);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public StringToIntConverter zzoh() {
        return this.zzabA;
    }

    public FastJsonResponse.zza<?, ?> zzoi() {
        if (this.zzabA != null) {
            return this.zzabA;
        }
        throw new IllegalStateException("There was no converter wrapped in this ConverterWrapper.");
    }
}
