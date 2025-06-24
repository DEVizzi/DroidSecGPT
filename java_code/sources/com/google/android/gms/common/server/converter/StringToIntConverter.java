package com.google.android.gms.common.server.converter;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.server.response.FastJsonResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
/* loaded from: classes.dex */
public final class StringToIntConverter implements SafeParcelable, FastJsonResponse.zza<String, Integer> {
    public static final zzb CREATOR = new zzb();
    private final int zzCY;
    private final HashMap<String, Integer> zzabB;
    private final HashMap<Integer, String> zzabC;
    private final ArrayList<Entry> zzabD;

    /* loaded from: classes.dex */
    public static final class Entry implements SafeParcelable {
        public static final zzc CREATOR = new zzc();
        final int versionCode;
        final String zzabE;
        final int zzabF;

        /* JADX INFO: Access modifiers changed from: package-private */
        public Entry(int versionCode, String stringValue, int intValue) {
            this.versionCode = versionCode;
            this.zzabE = stringValue;
            this.zzabF = intValue;
        }

        Entry(String stringValue, int intValue) {
            this.versionCode = 1;
            this.zzabE = stringValue;
            this.zzabF = intValue;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            zzc zzcVar = CREATOR;
            return 0;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel out, int flags) {
            zzc zzcVar = CREATOR;
            zzc.zza(this, out, flags);
        }
    }

    public StringToIntConverter() {
        this.zzCY = 1;
        this.zzabB = new HashMap<>();
        this.zzabC = new HashMap<>();
        this.zzabD = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public StringToIntConverter(int versionCode, ArrayList<Entry> serializedMap) {
        this.zzCY = versionCode;
        this.zzabB = new HashMap<>();
        this.zzabC = new HashMap<>();
        this.zzabD = null;
        zzb(serializedMap);
    }

    private void zzb(ArrayList<Entry> arrayList) {
        Iterator<Entry> it = arrayList.iterator();
        while (it.hasNext()) {
            Entry next = it.next();
            zzh(next.zzabE, next.zzabF);
        }
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zzb zzbVar = CREATOR;
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzb zzbVar = CREATOR;
        zzb.zza(this, out, flags);
    }

    @Override // com.google.android.gms.common.server.response.FastJsonResponse.zza
    /* renamed from: zzb */
    public String convertBack(Integer num) {
        String str = this.zzabC.get(num);
        return (str == null && this.zzabB.containsKey("gms_unknown")) ? "gms_unknown" : str;
    }

    public StringToIntConverter zzh(String str, int i) {
        this.zzabB.put(str, Integer.valueOf(i));
        this.zzabC.put(Integer.valueOf(i), str);
        return this;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ArrayList<Entry> zzoj() {
        ArrayList<Entry> arrayList = new ArrayList<>();
        for (String str : this.zzabB.keySet()) {
            arrayList.add(new Entry(str, this.zzabB.get(str).intValue()));
        }
        return arrayList;
    }

    @Override // com.google.android.gms.common.server.response.FastJsonResponse.zza
    public int zzok() {
        return 7;
    }

    @Override // com.google.android.gms.common.server.response.FastJsonResponse.zza
    public int zzol() {
        return 0;
    }
}
