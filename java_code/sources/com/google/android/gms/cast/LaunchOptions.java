package com.google.android.gms.cast;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.cast.internal.zzf;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import java.util.Locale;
/* loaded from: classes.dex */
public class LaunchOptions implements SafeParcelable {
    public static final Parcelable.Creator<LaunchOptions> CREATOR = new zzc();
    private final int zzCY;
    private String zzRA;
    private boolean zzRz;

    /* loaded from: classes.dex */
    public static final class Builder {
        private LaunchOptions zzRB = new LaunchOptions();

        public LaunchOptions build() {
            return this.zzRB;
        }

        public Builder setLocale(Locale locale) {
            this.zzRB.setLanguage(zzf.zzb(locale));
            return this;
        }

        public Builder setRelaunchIfRunning(boolean relaunchIfRunning) {
            this.zzRB.setRelaunchIfRunning(relaunchIfRunning);
            return this;
        }
    }

    public LaunchOptions() {
        this(1, false, zzf.zzb(Locale.getDefault()));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LaunchOptions(int versionCode, boolean relaunchIfRunning, String language) {
        this.zzCY = versionCode;
        this.zzRz = relaunchIfRunning;
        this.zzRA = language;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof LaunchOptions) {
            LaunchOptions launchOptions = (LaunchOptions) obj;
            return this.zzRz == launchOptions.zzRz && zzf.zza(this.zzRA, launchOptions.zzRA);
        }
        return false;
    }

    public String getLanguage() {
        return this.zzRA;
    }

    public boolean getRelaunchIfRunning() {
        return this.zzRz;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return zzt.hashCode(Boolean.valueOf(this.zzRz), this.zzRA);
    }

    public void setLanguage(String language) {
        this.zzRA = language;
    }

    public void setRelaunchIfRunning(boolean relaunchIfRunning) {
        this.zzRz = relaunchIfRunning;
    }

    public String toString() {
        return String.format("LaunchOptions(relaunchIfRunning=%b, language=%s)", Boolean.valueOf(this.zzRz), this.zzRA);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzc.zza(this, out, flags);
    }
}
