package com.google.android.gms.fitness.data;

import android.content.Context;
import android.content.Intent;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
/* loaded from: classes.dex */
public class DataSource implements SafeParcelable {
    public static final Parcelable.Creator<DataSource> CREATOR = new zzf();
    public static final String EXTRA_DATA_SOURCE = "vnd.google.fitness.data_source";
    public static final int TYPE_DERIVED = 1;
    public static final int TYPE_RAW = 0;
    private final String mName;
    private final int zzCY;
    private final int zzSq;
    private final DataType zzajF;
    private final Device zzakd;
    private final Application zzake;
    private final String zzakf;
    private final String zzakg;

    /* loaded from: classes.dex */
    public static final class Builder {
        private String mName;
        private DataType zzajF;
        private Device zzakd;
        private Application zzake;
        private int zzSq = -1;
        private String zzakf = "";

        public DataSource build() {
            zzu.zza(this.zzajF != null, "Must set data type");
            zzu.zza(this.zzSq >= 0, "Must set data source type");
            return new DataSource(this);
        }

        public Builder setAppPackageName(Context appContext) {
            return setAppPackageName(appContext.getPackageName());
        }

        public Builder setAppPackageName(String packageName) {
            this.zzake = Application.zzcG(packageName);
            return this;
        }

        public Builder setDataType(DataType dataType) {
            this.zzajF = dataType;
            return this;
        }

        public Builder setDevice(Device device) {
            this.zzakd = device;
            return this;
        }

        public Builder setName(String name) {
            this.mName = name;
            return this;
        }

        public Builder setStreamName(String streamName) {
            zzu.zzb(streamName != null, "Must specify a valid stream name");
            this.zzakf = streamName;
            return this;
        }

        public Builder setType(int type) {
            this.zzSq = type;
            return this;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DataSource(int versionCode, DataType dataType, String name, int type, Device device, Application application, String streamName) {
        this.zzCY = versionCode;
        this.zzajF = dataType;
        this.zzSq = type;
        this.mName = name;
        this.zzakd = device;
        this.zzake = application;
        this.zzakf = streamName;
        this.zzakg = zzqC();
    }

    private DataSource(Builder builder) {
        this.zzCY = 3;
        this.zzajF = builder.zzajF;
        this.zzSq = builder.zzSq;
        this.mName = builder.mName;
        this.zzakd = builder.zzakd;
        this.zzake = builder.zzake;
        this.zzakf = builder.zzakf;
        this.zzakg = zzqC();
    }

    public static DataSource extract(Intent intent) {
        if (intent == null) {
            return null;
        }
        return (DataSource) com.google.android.gms.common.internal.safeparcel.zzc.zza(intent, EXTRA_DATA_SOURCE, CREATOR);
    }

    private String getTypeString() {
        switch (this.zzSq) {
            case 0:
                return "raw";
            case 1:
                return "derived";
            default:
                throw new IllegalArgumentException("invalid type value");
        }
    }

    private boolean zza(DataSource dataSource) {
        return this.zzakg.equals(dataSource.zzakg);
    }

    private String zzqC() {
        StringBuilder sb = new StringBuilder();
        sb.append(getTypeString());
        sb.append(":").append(this.zzajF.getName());
        if (this.zzake != null) {
            sb.append(":").append(this.zzake.getPackageName());
        }
        if (this.zzakd != null) {
            sb.append(":").append(this.zzakd.getStreamIdentifier());
        }
        if (this.zzakf != null) {
            sb.append(":").append(this.zzakf);
        }
        return sb.toString();
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object that) {
        return this == that || ((that instanceof DataSource) && zza((DataSource) that));
    }

    public String getAppPackageName() {
        if (this.zzake == null) {
            return null;
        }
        return this.zzake.getPackageName();
    }

    public DataType getDataType() {
        return this.zzajF;
    }

    public Device getDevice() {
        return this.zzakd;
    }

    public String getName() {
        return this.mName;
    }

    public String getStreamIdentifier() {
        return this.zzakg;
    }

    public String getStreamName() {
        return this.zzakf;
    }

    public int getType() {
        return this.zzSq;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return this.zzakg.hashCode();
    }

    public String toDebugString() {
        return (this.zzSq == 0 ? "r" : "d") + ":" + this.zzajF.zzqD() + (this.zzake == null ? "" : this.zzake.equals(Application.zzajM) ? ":gms" : ":" + this.zzake.getPackageName()) + (this.zzakd != null ? ":" + this.zzakd.getModel() + ":" + this.zzakd.getUid() : "") + (this.zzakf != null ? ":" + this.zzakf : "");
    }

    public String toString() {
        StringBuilder sb = new StringBuilder("DataSource{");
        sb.append(getTypeString());
        if (this.mName != null) {
            sb.append(":").append(this.mName);
        }
        if (this.zzake != null) {
            sb.append(":").append(this.zzake);
        }
        if (this.zzakd != null) {
            sb.append(":").append(this.zzakd);
        }
        if (this.zzakf != null) {
            sb.append(":").append(this.zzakf);
        }
        sb.append(":").append(this.zzajF);
        return sb.append("}").toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzf.zza(this, parcel, flags);
    }

    public Application zzqB() {
        return this.zzake;
    }
}
