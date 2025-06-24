package com.google.android.gms.common.server.response;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.common.server.response.FastJsonResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
public class FieldMappingDictionary implements SafeParcelable {
    public static final zzc CREATOR = new zzc();
    private final int zzCY;
    private final HashMap<String, Map<String, FastJsonResponse.Field<?, ?>>> zzabQ;
    private final ArrayList<Entry> zzabR;
    private final String zzabS;

    /* loaded from: classes.dex */
    public static class Entry implements SafeParcelable {
        public static final zzd CREATOR = new zzd();
        final String className;
        final int versionCode;
        final ArrayList<FieldMapPair> zzabT;

        /* JADX INFO: Access modifiers changed from: package-private */
        public Entry(int versionCode, String className, ArrayList<FieldMapPair> fieldMapping) {
            this.versionCode = versionCode;
            this.className = className;
            this.zzabT = fieldMapping;
        }

        Entry(String className, Map<String, FastJsonResponse.Field<?, ?>> fieldMap) {
            this.versionCode = 1;
            this.className = className;
            this.zzabT = zzB(fieldMap);
        }

        private static ArrayList<FieldMapPair> zzB(Map<String, FastJsonResponse.Field<?, ?>> map) {
            if (map == null) {
                return null;
            }
            ArrayList<FieldMapPair> arrayList = new ArrayList<>();
            for (String str : map.keySet()) {
                arrayList.add(new FieldMapPair(str, map.get(str)));
            }
            return arrayList;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            zzd zzdVar = CREATOR;
            return 0;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel out, int flags) {
            zzd zzdVar = CREATOR;
            zzd.zza(this, out, flags);
        }

        HashMap<String, FastJsonResponse.Field<?, ?>> zzoD() {
            HashMap<String, FastJsonResponse.Field<?, ?>> hashMap = new HashMap<>();
            int size = this.zzabT.size();
            for (int i = 0; i < size; i++) {
                FieldMapPair fieldMapPair = this.zzabT.get(i);
                hashMap.put(fieldMapPair.zzaC, fieldMapPair.zzabU);
            }
            return hashMap;
        }
    }

    /* loaded from: classes.dex */
    public static class FieldMapPair implements SafeParcelable {
        public static final zzb CREATOR = new zzb();
        final int versionCode;
        final String zzaC;
        final FastJsonResponse.Field<?, ?> zzabU;

        /* JADX INFO: Access modifiers changed from: package-private */
        public FieldMapPair(int versionCode, String key, FastJsonResponse.Field<?, ?> value) {
            this.versionCode = versionCode;
            this.zzaC = key;
            this.zzabU = value;
        }

        FieldMapPair(String key, FastJsonResponse.Field<?, ?> value) {
            this.versionCode = 1;
            this.zzaC = key;
            this.zzabU = value;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            zzb zzbVar = CREATOR;
            return 0;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel out, int flags) {
            zzb zzbVar = CREATOR;
            zzb.zza(this, out, flags);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public FieldMappingDictionary(int versionCode, ArrayList<Entry> serializedDictionary, String rootClassName) {
        this.zzCY = versionCode;
        this.zzabR = null;
        this.zzabQ = zzc(serializedDictionary);
        this.zzabS = (String) zzu.zzu(rootClassName);
        zzoz();
    }

    public FieldMappingDictionary(Class<? extends FastJsonResponse> rootClazz) {
        this.zzCY = 1;
        this.zzabR = null;
        this.zzabQ = new HashMap<>();
        this.zzabS = rootClazz.getCanonicalName();
    }

    private static HashMap<String, Map<String, FastJsonResponse.Field<?, ?>>> zzc(ArrayList<Entry> arrayList) {
        HashMap<String, Map<String, FastJsonResponse.Field<?, ?>>> hashMap = new HashMap<>();
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            Entry entry = arrayList.get(i);
            hashMap.put(entry.className, entry.zzoD());
        }
        return hashMap;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zzc zzcVar = CREATOR;
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (String str : this.zzabQ.keySet()) {
            sb.append(str).append(":\n");
            Map<String, FastJsonResponse.Field<?, ?>> map = this.zzabQ.get(str);
            for (String str2 : map.keySet()) {
                sb.append("  ").append(str2).append(": ");
                sb.append(map.get(str2));
            }
        }
        return sb.toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzc zzcVar = CREATOR;
        zzc.zza(this, out, flags);
    }

    public void zza(Class<? extends FastJsonResponse> cls, Map<String, FastJsonResponse.Field<?, ?>> map) {
        this.zzabQ.put(cls.getCanonicalName(), map);
    }

    public boolean zzb(Class<? extends FastJsonResponse> cls) {
        return this.zzabQ.containsKey(cls.getCanonicalName());
    }

    public Map<String, FastJsonResponse.Field<?, ?>> zzco(String str) {
        return this.zzabQ.get(str);
    }

    public void zzoA() {
        for (String str : this.zzabQ.keySet()) {
            Map<String, FastJsonResponse.Field<?, ?>> map = this.zzabQ.get(str);
            HashMap hashMap = new HashMap();
            for (String str2 : map.keySet()) {
                hashMap.put(str2, map.get(str2).zzop());
            }
            this.zzabQ.put(str, hashMap);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ArrayList<Entry> zzoB() {
        ArrayList<Entry> arrayList = new ArrayList<>();
        for (String str : this.zzabQ.keySet()) {
            arrayList.add(new Entry(str, this.zzabQ.get(str)));
        }
        return arrayList;
    }

    public String zzoC() {
        return this.zzabS;
    }

    public void zzoz() {
        for (String str : this.zzabQ.keySet()) {
            Map<String, FastJsonResponse.Field<?, ?>> map = this.zzabQ.get(str);
            for (String str2 : map.keySet()) {
                map.get(str2).zza(this);
            }
        }
    }
}
