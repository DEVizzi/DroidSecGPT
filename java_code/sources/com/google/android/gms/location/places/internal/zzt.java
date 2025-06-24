package com.google.android.gms.location.places.internal;

import android.os.Parcelable;
import android.util.Log;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.internal.zzrd;
import com.google.android.gms.internal.zzrm;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
/* loaded from: classes.dex */
public abstract class zzt extends com.google.android.gms.common.data.zzc {
    private final String TAG;

    public zzt(DataHolder dataHolder, int i) {
        super(dataHolder, i);
        this.TAG = "SafeDataBufferRef";
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public String zzB(String str, String str2) {
        return (!zzbV(str) || zzbX(str)) ? str2 : getString(str);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public <E extends SafeParcelable> E zza(String str, Parcelable.Creator<E> creator) {
        byte[] zzc = zzc(str, null);
        if (zzc == null) {
            return null;
        }
        return (E) com.google.android.gms.common.internal.safeparcel.zzc.zza(zzc, creator);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public <E extends SafeParcelable> List<E> zza(String str, Parcelable.Creator<E> creator, List<E> list) {
        byte[] zzc = zzc(str, null);
        if (zzc == null) {
            return list;
        }
        try {
            zzrd zzx = zzrd.zzx(zzc);
            if (zzx.zzaVG != null) {
                ArrayList arrayList = new ArrayList(zzx.zzaVG.length);
                byte[][] bArr = zzx.zzaVG;
                for (byte[] bArr2 : bArr) {
                    arrayList.add(com.google.android.gms.common.internal.safeparcel.zzc.zza(bArr2, creator));
                }
                return arrayList;
            }
            return list;
        } catch (zzrm e) {
            if (Log.isLoggable("SafeDataBufferRef", 6)) {
                Log.e("SafeDataBufferRef", "Cannot parse byte[]", e);
                return list;
            }
            return list;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public List<Integer> zza(String str, List<Integer> list) {
        byte[] zzc = zzc(str, null);
        if (zzc == null) {
            return list;
        }
        try {
            zzrd zzx = zzrd.zzx(zzc);
            if (zzx.zzaVF != null) {
                ArrayList arrayList = new ArrayList(zzx.zzaVF.length);
                for (int i = 0; i < zzx.zzaVF.length; i++) {
                    arrayList.add(Integer.valueOf(zzx.zzaVF[i]));
                }
                return arrayList;
            }
            return list;
        } catch (zzrm e) {
            if (Log.isLoggable("SafeDataBufferRef", 6)) {
                Log.e("SafeDataBufferRef", "Cannot parse byte[]", e);
                return list;
            }
            return list;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public float zzb(String str, float f) {
        return (!zzbV(str) || zzbX(str)) ? f : getFloat(str);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public List<String> zzb(String str, List<String> list) {
        byte[] zzc = zzc(str, null);
        if (zzc == null) {
            return list;
        }
        try {
            zzrd zzx = zzrd.zzx(zzc);
            return zzx.zzaVE != null ? Arrays.asList(zzx.zzaVE) : list;
        } catch (zzrm e) {
            if (Log.isLoggable("SafeDataBufferRef", 6)) {
                Log.e("SafeDataBufferRef", "Cannot parse byte[]", e);
                return list;
            }
            return list;
        }
    }

    protected byte[] zzc(String str, byte[] bArr) {
        return (!zzbV(str) || zzbX(str)) ? bArr : getByteArray(str);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public boolean zzh(String str, boolean z) {
        return (!zzbV(str) || zzbX(str)) ? z : getBoolean(str);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public int zzz(String str, int i) {
        return (!zzbV(str) || zzbX(str)) ? i : getInteger(str);
    }
}
