package com.google.android.gms.nearby.messages;

import android.os.Parcel;
import android.os.Parcelable;
import android.support.v7.internal.widget.ActivityChooserView;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
/* loaded from: classes.dex */
public class Strategy implements SafeParcelable {
    public static final Parcelable.Creator<Strategy> CREATOR = new zzf();
    public static final Strategy zzaFQ = new zza().zzwZ();
    public static final Strategy zzaFR = new zza().zzie(2).zzif(ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED).zzwZ();
    @Deprecated
    public static final Strategy zzaFS = zzaFR;
    final int versionCode;
    @Deprecated
    final int zzaFT;
    final int zzaFU;
    final int zzaFV;
    @Deprecated
    final boolean zzaFW;
    final int zzaFX;
    final int zzaFY;

    /* loaded from: classes.dex */
    public static class zza {
        private int zzaFY = 3;
        private int zzaFU = 300;
        private int zzaFV = 0;
        private int zzaFX = 1;

        public zza zzie(int i) {
            this.zzaFX = i;
            return this;
        }

        public zza zzif(int i) {
            zzu.zzb(i == Integer.MAX_VALUE || (i > 0 && i <= 86400), "ttlSeconds(%d) must either be TTL_SECONDS_INFINITE, or it must be between 1 and TTL_SECONDS_MAX(%d) inclusive", Integer.valueOf(i), 86400);
            this.zzaFU = i;
            return this;
        }

        public Strategy zzwZ() {
            if (this.zzaFX == 2) {
                if (this.zzaFY != 3) {
                    throw new IllegalStateException("Discovery mode must be DISCOVERY_MODE_DEFAULT.");
                }
                if (this.zzaFV == 1) {
                    throw new IllegalStateException("Cannot set EARSHOT with BLE only mode.");
                }
            }
            return new Strategy(2, 0, this.zzaFU, this.zzaFV, false, this.zzaFX, this.zzaFY);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Strategy(int versionCode, int broadcastScanStrategy, int ttlSeconds, int distanceType, boolean isBleBeaconStrategy, int discoveryMedium, int discoveryMode) {
        this.versionCode = versionCode;
        this.zzaFT = broadcastScanStrategy;
        if (broadcastScanStrategy != 0) {
            switch (broadcastScanStrategy) {
                case 2:
                    this.zzaFY = 1;
                    break;
                case 3:
                    this.zzaFY = 2;
                    break;
                default:
                    this.zzaFY = 3;
                    break;
            }
        } else {
            this.zzaFY = discoveryMode;
        }
        this.zzaFV = distanceType;
        this.zzaFW = isBleBeaconStrategy;
        if (isBleBeaconStrategy) {
            this.zzaFX = 2;
            this.zzaFU = ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        } else if (discoveryMedium == 0) {
            this.zzaFX = 1;
            this.zzaFU = ttlSeconds;
        } else {
            this.zzaFX = discoveryMedium;
            this.zzaFU = ttlSeconds;
        }
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other instanceof Strategy) {
            Strategy strategy = (Strategy) other;
            return this.versionCode == strategy.versionCode && this.zzaFY == strategy.zzaFY && this.zzaFU == strategy.zzaFU && this.zzaFV == strategy.zzaFV && this.zzaFX == strategy.zzaFX;
        }
        return false;
    }

    public int hashCode() {
        return (((((((this.versionCode * 31) + this.zzaFY) * 31) + this.zzaFU) * 31) + this.zzaFV) * 31) + this.zzaFX;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzf.zza(this, out, flags);
    }
}
