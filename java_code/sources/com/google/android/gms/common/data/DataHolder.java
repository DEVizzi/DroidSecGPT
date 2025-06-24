package com.google.android.gms.common.data;

import android.database.CharArrayBuffer;
import android.database.CursorIndexOutOfBoundsException;
import android.database.CursorWindow;
import android.net.Uri;
import android.os.Bundle;
import android.os.Parcel;
import android.util.Log;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
public final class DataHolder implements SafeParcelable {
    public static final zze CREATOR = new zze();
    private static final zza zzYE = new zza(new String[0], null) { // from class: com.google.android.gms.common.data.DataHolder.1
    };
    boolean mClosed;
    private final int zzCY;
    private final int zzTS;
    int[] zzYA;
    int zzYB;
    private Object zzYC;
    private boolean zzYD;
    private final String[] zzYw;
    Bundle zzYx;
    private final CursorWindow[] zzYy;
    private final Bundle zzYz;

    /* loaded from: classes.dex */
    public static class zza {
        private final ArrayList<HashMap<String, Object>> zzYF;
        private final String zzYG;
        private final HashMap<Object, Integer> zzYH;
        private boolean zzYI;
        private String zzYJ;
        private final String[] zzYw;

        private zza(String[] strArr, String str) {
            this.zzYw = (String[]) zzu.zzu(strArr);
            this.zzYF = new ArrayList<>();
            this.zzYG = str;
            this.zzYH = new HashMap<>();
            this.zzYI = false;
            this.zzYJ = null;
        }
    }

    /* loaded from: classes.dex */
    public static class zzb extends RuntimeException {
        public zzb(String str) {
            super(str);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DataHolder(int versionCode, String[] columns, CursorWindow[] windows, int statusCode, Bundle metadata) {
        this.mClosed = false;
        this.zzYD = true;
        this.zzCY = versionCode;
        this.zzYw = columns;
        this.zzYy = windows;
        this.zzTS = statusCode;
        this.zzYz = metadata;
    }

    private DataHolder(zza builder, int statusCode, Bundle metadata) {
        this(builder.zzYw, zza(builder, -1), statusCode, metadata);
    }

    public DataHolder(String[] columns, CursorWindow[] windows, int statusCode, Bundle metadata) {
        this.mClosed = false;
        this.zzYD = true;
        this.zzCY = 1;
        this.zzYw = (String[]) zzu.zzu(columns);
        this.zzYy = (CursorWindow[]) zzu.zzu(windows);
        this.zzTS = statusCode;
        this.zzYz = metadata;
        zznf();
    }

    public static DataHolder zza(int i, Bundle bundle) {
        return new DataHolder(zzYE, i, bundle);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v38, types: [java.util.List] */
    private static CursorWindow[] zza(zza zzaVar, int i) {
        int i2;
        boolean z;
        CursorWindow cursorWindow;
        if (zzaVar.zzYw.length == 0) {
            return new CursorWindow[0];
        }
        ArrayList subList = (i < 0 || i >= zzaVar.zzYF.size()) ? zzaVar.zzYF : zzaVar.zzYF.subList(0, i);
        int size = subList.size();
        CursorWindow cursorWindow2 = new CursorWindow(false);
        ArrayList arrayList = new ArrayList();
        arrayList.add(cursorWindow2);
        cursorWindow2.setNumColumns(zzaVar.zzYw.length);
        int i3 = 0;
        boolean z2 = false;
        while (i3 < size) {
            try {
                if (!cursorWindow2.allocRow()) {
                    Log.d("DataHolder", "Allocating additional cursor window for large data set (row " + i3 + ")");
                    cursorWindow2 = new CursorWindow(false);
                    cursorWindow2.setStartPosition(i3);
                    cursorWindow2.setNumColumns(zzaVar.zzYw.length);
                    arrayList.add(cursorWindow2);
                    if (!cursorWindow2.allocRow()) {
                        Log.e("DataHolder", "Unable to allocate row to hold data.");
                        arrayList.remove(cursorWindow2);
                        return (CursorWindow[]) arrayList.toArray(new CursorWindow[arrayList.size()]);
                    }
                }
                Map map = (Map) subList.get(i3);
                boolean z3 = true;
                for (int i4 = 0; i4 < zzaVar.zzYw.length && z3; i4++) {
                    String str = zzaVar.zzYw[i4];
                    Object obj = map.get(str);
                    if (obj == null) {
                        z3 = cursorWindow2.putNull(i3, i4);
                    } else if (obj instanceof String) {
                        z3 = cursorWindow2.putString((String) obj, i3, i4);
                    } else if (obj instanceof Long) {
                        z3 = cursorWindow2.putLong(((Long) obj).longValue(), i3, i4);
                    } else if (obj instanceof Integer) {
                        z3 = cursorWindow2.putLong(((Integer) obj).intValue(), i3, i4);
                    } else if (obj instanceof Boolean) {
                        z3 = cursorWindow2.putLong(((Boolean) obj).booleanValue() ? 1L : 0L, i3, i4);
                    } else if (obj instanceof byte[]) {
                        z3 = cursorWindow2.putBlob((byte[]) obj, i3, i4);
                    } else if (obj instanceof Double) {
                        z3 = cursorWindow2.putDouble(((Double) obj).doubleValue(), i3, i4);
                    } else if (!(obj instanceof Float)) {
                        throw new IllegalArgumentException("Unsupported object for column " + str + ": " + obj);
                    } else {
                        z3 = cursorWindow2.putDouble(((Float) obj).floatValue(), i3, i4);
                    }
                }
                if (z3) {
                    i2 = i3;
                    z = false;
                    cursorWindow = cursorWindow2;
                } else if (z2) {
                    throw new zzb("Could not add the value to a new CursorWindow. The size of value may be larger than what a CursorWindow can handle.");
                } else {
                    Log.d("DataHolder", "Couldn't populate window data for row " + i3 + " - allocating new window.");
                    cursorWindow2.freeLastRow();
                    CursorWindow cursorWindow3 = new CursorWindow(false);
                    cursorWindow3.setStartPosition(i3);
                    cursorWindow3.setNumColumns(zzaVar.zzYw.length);
                    arrayList.add(cursorWindow3);
                    i2 = i3 - 1;
                    cursorWindow = cursorWindow3;
                    z = true;
                }
                z2 = z;
                cursorWindow2 = cursorWindow;
                i3 = i2 + 1;
            } catch (RuntimeException e) {
                int size2 = arrayList.size();
                for (int i5 = 0; i5 < size2; i5++) {
                    ((CursorWindow) arrayList.get(i5)).close();
                }
                throw e;
            }
        }
        return (CursorWindow[]) arrayList.toArray(new CursorWindow[arrayList.size()]);
    }

    public static DataHolder zzbi(int i) {
        return zza(i, (Bundle) null);
    }

    private void zzg(String str, int i) {
        if (this.zzYx == null || !this.zzYx.containsKey(str)) {
            throw new IllegalArgumentException("No such column: " + str);
        }
        if (isClosed()) {
            throw new IllegalArgumentException("Buffer is closed.");
        }
        if (i < 0 || i >= this.zzYB) {
            throw new CursorIndexOutOfBoundsException(i, this.zzYB);
        }
    }

    public void close() {
        synchronized (this) {
            if (!this.mClosed) {
                this.mClosed = true;
                for (int i = 0; i < this.zzYy.length; i++) {
                    this.zzYy[i].close();
                }
            }
        }
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    protected void finalize() throws Throwable {
        try {
            if (this.zzYD && this.zzYy.length > 0 && !isClosed()) {
                Log.e("DataBuffer", "Internal data leak within a DataBuffer object detected!  Be sure to explicitly call release() on all DataBuffer extending objects when you are done with them. (" + (this.zzYC == null ? "internal object: " + toString() : this.zzYC.toString()) + ")");
                close();
            }
        } finally {
            super.finalize();
        }
    }

    public int getCount() {
        return this.zzYB;
    }

    public int getStatusCode() {
        return this.zzTS;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public boolean isClosed() {
        boolean z;
        synchronized (this) {
            z = this.mClosed;
        }
        return z;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zze.zza(this, dest, flags);
    }

    public void zza(String str, int i, int i2, CharArrayBuffer charArrayBuffer) {
        zzg(str, i);
        this.zzYy[i2].copyStringToBuffer(i, this.zzYx.getInt(str), charArrayBuffer);
    }

    public long zzb(String str, int i, int i2) {
        zzg(str, i);
        return this.zzYy[i2].getLong(i, this.zzYx.getInt(str));
    }

    public boolean zzbV(String str) {
        return this.zzYx.containsKey(str);
    }

    public int zzbh(int i) {
        int i2 = 0;
        zzu.zzU(i >= 0 && i < this.zzYB);
        while (true) {
            if (i2 >= this.zzYA.length) {
                break;
            } else if (i < this.zzYA[i2]) {
                i2--;
                break;
            } else {
                i2++;
            }
        }
        return i2 == this.zzYA.length ? i2 - 1 : i2;
    }

    public int zzc(String str, int i, int i2) {
        zzg(str, i);
        return this.zzYy[i2].getInt(i, this.zzYx.getInt(str));
    }

    public String zzd(String str, int i, int i2) {
        zzg(str, i);
        return this.zzYy[i2].getString(i, this.zzYx.getInt(str));
    }

    public boolean zze(String str, int i, int i2) {
        zzg(str, i);
        return Long.valueOf(this.zzYy[i2].getLong(i, this.zzYx.getInt(str))).longValue() == 1;
    }

    public float zzf(String str, int i, int i2) {
        zzg(str, i);
        return this.zzYy[i2].getFloat(i, this.zzYx.getInt(str));
    }

    public byte[] zzg(String str, int i, int i2) {
        zzg(str, i);
        return this.zzYy[i2].getBlob(i, this.zzYx.getInt(str));
    }

    public Uri zzh(String str, int i, int i2) {
        String zzd = zzd(str, i, i2);
        if (zzd == null) {
            return null;
        }
        return Uri.parse(zzd);
    }

    public boolean zzi(String str, int i, int i2) {
        zzg(str, i);
        return this.zzYy[i2].isNull(i, this.zzYx.getInt(str));
    }

    public Bundle zznb() {
        return this.zzYz;
    }

    public void zznf() {
        this.zzYx = new Bundle();
        for (int i = 0; i < this.zzYw.length; i++) {
            this.zzYx.putInt(this.zzYw[i], i);
        }
        this.zzYA = new int[this.zzYy.length];
        int i2 = 0;
        for (int i3 = 0; i3 < this.zzYy.length; i3++) {
            this.zzYA[i3] = i2;
            i2 += this.zzYy[i3].getNumRows() - (i2 - this.zzYy[i3].getStartPosition());
        }
        this.zzYB = i2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String[] zzng() {
        return this.zzYw;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CursorWindow[] zznh() {
        return this.zzYy;
    }

    public void zzp(Object obj) {
        this.zzYC = obj;
    }
}
