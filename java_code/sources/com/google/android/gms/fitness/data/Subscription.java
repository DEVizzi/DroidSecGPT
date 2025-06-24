package com.google.android.gms.fitness.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
/* loaded from: classes.dex */
public class Subscription implements SafeParcelable {
    public static final Parcelable.Creator<Subscription> CREATOR = new zzr();
    private final int zzCY;
    private final DataType zzajF;
    private final DataSource zzajG;
    private final long zzakP;
    private final int zzakQ;

    /* loaded from: classes.dex */
    public static class zza {
        private DataType zzajF;
        private DataSource zzajG;
        private long zzakP = -1;
        private int zzakQ = 2;

        public zza zzb(DataSource dataSource) {
            this.zzajG = dataSource;
            return this;
        }

        public zza zzb(DataType dataType) {
            this.zzajF = dataType;
            return this;
        }

        public Subscription zzqN() {
            boolean z = false;
            zzu.zza((this.zzajG == null && this.zzajF == null) ? false : true, "Must call setDataSource() or setDataType()");
            if (this.zzajF == null || this.zzajG == null || this.zzajF.equals(this.zzajG.getDataType())) {
                z = true;
            }
            zzu.zza(z, "Specified data type is incompatible with specified data source");
            return new Subscription(this);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Subscription(int versionCode, DataSource dataSource, DataType dataType, long samplingIntervalMicros, int accuracyMode) {
        this.zzCY = versionCode;
        this.zzajG = dataSource;
        this.zzajF = dataType;
        this.zzakP = samplingIntervalMicros;
        this.zzakQ = accuracyMode;
    }

    private Subscription(zza builder) {
        this.zzCY = 1;
        this.zzajF = builder.zzajF;
        this.zzajG = builder.zzajG;
        this.zzakP = builder.zzakP;
        this.zzakQ = builder.zzakQ;
    }

    private boolean zza(Subscription subscription) {
        return com.google.android.gms.common.internal.zzt.equal(this.zzajG, subscription.zzajG) && com.google.android.gms.common.internal.zzt.equal(this.zzajF, subscription.zzajF) && this.zzakP == subscription.zzakP && this.zzakQ == subscription.zzakQ;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object that) {
        return this == that || ((that instanceof Subscription) && zza((Subscription) that));
    }

    public int getAccuracyMode() {
        return this.zzakQ;
    }

    public DataSource getDataSource() {
        return this.zzajG;
    }

    public DataType getDataType() {
        return this.zzajF;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(this.zzajG, this.zzajG, Long.valueOf(this.zzakP), Integer.valueOf(this.zzakQ));
    }

    public String toDebugString() {
        Object[] objArr = new Object[1];
        objArr[0] = this.zzajG == null ? this.zzajF.getName() : this.zzajG.toDebugString();
        return String.format("Subscription{%s}", objArr);
    }

    public String toString() {
        return com.google.android.gms.common.internal.zzt.zzt(this).zzg("dataSource", this.zzajG).zzg("dataType", this.zzajF).zzg("samplingIntervalMicros", Long.valueOf(this.zzakP)).zzg("accuracyMode", Integer.valueOf(this.zzakQ)).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzr.zza(this, dest, flags);
    }

    public long zzqL() {
        return this.zzakP;
    }

    public DataType zzqM() {
        return this.zzajF == null ? this.zzajG.getDataType() : this.zzajF;
    }
}
