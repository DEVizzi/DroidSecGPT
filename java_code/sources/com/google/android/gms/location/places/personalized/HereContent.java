package com.google.android.gms.location.places.personalized;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.plus.PlusShare;
import java.util.List;
/* loaded from: classes.dex */
public class HereContent implements SafeParcelable {
    public static final zzb CREATOR = new zzb();
    final int zzCY;
    private final String zzaBe;
    private final List<Action> zzaBf;

    /* loaded from: classes.dex */
    public static final class Action implements SafeParcelable {
        public static final zza CREATOR = new zza();
        final int zzCY;
        private final String zzNb;
        private final String zzadv;

        /* JADX INFO: Access modifiers changed from: package-private */
        public Action(int versionCode, String title, String uri) {
            this.zzCY = versionCode;
            this.zzadv = title;
            this.zzNb = uri;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            zza zzaVar = CREATOR;
            return 0;
        }

        public boolean equals(Object object) {
            if (this == object) {
                return true;
            }
            if (object instanceof Action) {
                Action action = (Action) object;
                return zzt.equal(this.zzadv, action.zzadv) && zzt.equal(this.zzNb, action.zzNb);
            }
            return false;
        }

        public String getTitle() {
            return this.zzadv;
        }

        public String getUri() {
            return this.zzNb;
        }

        public int hashCode() {
            return zzt.hashCode(this.zzadv, this.zzNb);
        }

        public String toString() {
            return zzt.zzt(this).zzg(PlusShare.KEY_CONTENT_DEEP_LINK_METADATA_TITLE, this.zzadv).zzg("uri", this.zzNb).toString();
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel parcel, int flags) {
            zza zzaVar = CREATOR;
            zza.zza(this, parcel, flags);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public HereContent(int versionCode, String data, List<Action> actions) {
        this.zzCY = versionCode;
        this.zzaBe = data;
        this.zzaBf = actions;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zzb zzbVar = CREATOR;
        return 0;
    }

    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object instanceof HereContent) {
            HereContent hereContent = (HereContent) object;
            return zzt.equal(this.zzaBe, hereContent.zzaBe) && zzt.equal(this.zzaBf, hereContent.zzaBf);
        }
        return false;
    }

    public List<Action> getActions() {
        return this.zzaBf;
    }

    public String getData() {
        return this.zzaBe;
    }

    public int hashCode() {
        return zzt.hashCode(this.zzaBe, this.zzaBf);
    }

    public String toString() {
        return zzt.zzt(this).zzg("data", this.zzaBe).zzg("actions", this.zzaBf).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzb zzbVar = CREATOR;
        zzb.zza(this, parcel, flags);
    }
}
