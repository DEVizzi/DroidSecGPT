package com.google.android.gms.internal;

import android.os.Bundle;
import android.os.Parcelable;
import android.os.SystemClock;
import com.google.android.gms.ads.internal.client.AdRequestParcel;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
@zzgd
/* loaded from: classes.dex */
public class zzhb {
    private boolean zzDY;
    private long zzFA;
    private long zzFB;
    private final LinkedList<zza> zzFt;
    private final String zzFu;
    private final String zzFv;
    private long zzFw;
    private long zzFx;
    private long zzFy;
    private long zzFz;
    private final zzhc zzpv;
    private final Object zzqt;

    /* JADX INFO: Access modifiers changed from: private */
    @zzgd
    /* loaded from: classes.dex */
    public static final class zza {
        private long zzFC = -1;
        private long zzFD = -1;

        public Bundle toBundle() {
            Bundle bundle = new Bundle();
            bundle.putLong("topen", this.zzFC);
            bundle.putLong("tclose", this.zzFD);
            return bundle;
        }

        public long zzfS() {
            return this.zzFD;
        }

        public void zzfT() {
            this.zzFD = SystemClock.elapsedRealtime();
        }

        public void zzfU() {
            this.zzFC = SystemClock.elapsedRealtime();
        }
    }

    public zzhb(zzhc zzhcVar, String str, String str2) {
        this.zzqt = new Object();
        this.zzFw = -1L;
        this.zzFx = -1L;
        this.zzDY = false;
        this.zzFy = -1L;
        this.zzFz = 0L;
        this.zzFA = -1L;
        this.zzFB = -1L;
        this.zzpv = zzhcVar;
        this.zzFu = str;
        this.zzFv = str2;
        this.zzFt = new LinkedList<>();
    }

    public zzhb(String str, String str2) {
        this(com.google.android.gms.ads.internal.zzo.zzby(), str, str2);
    }

    public Bundle toBundle() {
        Bundle bundle;
        synchronized (this.zzqt) {
            bundle = new Bundle();
            bundle.putString("seq_num", this.zzFu);
            bundle.putString("slotid", this.zzFv);
            bundle.putBoolean("ismediation", this.zzDY);
            bundle.putLong("treq", this.zzFA);
            bundle.putLong("tresponse", this.zzFB);
            bundle.putLong("timp", this.zzFx);
            bundle.putLong("tload", this.zzFy);
            bundle.putLong("pcc", this.zzFz);
            bundle.putLong("tfetch", this.zzFw);
            ArrayList<? extends Parcelable> arrayList = new ArrayList<>();
            Iterator<zza> it = this.zzFt.iterator();
            while (it.hasNext()) {
                arrayList.add(it.next().toBundle());
            }
            bundle.putParcelableArrayList("tclick", arrayList);
        }
        return bundle;
    }

    public void zzfP() {
        synchronized (this.zzqt) {
            if (this.zzFB != -1 && this.zzFx == -1) {
                this.zzFx = SystemClock.elapsedRealtime();
                this.zzpv.zza(this);
            }
            this.zzpv.zzfX().zzfP();
        }
    }

    public void zzfQ() {
        synchronized (this.zzqt) {
            if (this.zzFB != -1) {
                zza zzaVar = new zza();
                zzaVar.zzfU();
                this.zzFt.add(zzaVar);
                this.zzFz++;
                this.zzpv.zzfX().zzfQ();
                this.zzpv.zza(this);
            }
        }
    }

    public void zzfR() {
        synchronized (this.zzqt) {
            if (this.zzFB != -1 && !this.zzFt.isEmpty()) {
                zza last = this.zzFt.getLast();
                if (last.zzfS() == -1) {
                    last.zzfT();
                    this.zzpv.zza(this);
                }
            }
        }
    }

    public void zzh(AdRequestParcel adRequestParcel) {
        synchronized (this.zzqt) {
            this.zzFA = SystemClock.elapsedRealtime();
            this.zzpv.zzfX().zzb(adRequestParcel, this.zzFA);
        }
    }

    public void zzl(long j) {
        synchronized (this.zzqt) {
            this.zzFB = j;
            if (this.zzFB != -1) {
                this.zzpv.zza(this);
            }
        }
    }

    public void zzm(long j) {
        synchronized (this.zzqt) {
            if (this.zzFB != -1) {
                this.zzFw = j;
                this.zzpv.zza(this);
            }
        }
    }

    public void zzy(boolean z) {
        synchronized (this.zzqt) {
            if (this.zzFB != -1) {
                this.zzFy = SystemClock.elapsedRealtime();
                if (!z) {
                    this.zzFx = this.zzFy;
                    this.zzpv.zza(this);
                }
            }
        }
    }

    public void zzz(boolean z) {
        synchronized (this.zzqt) {
            if (this.zzFB != -1) {
                this.zzDY = z;
                this.zzpv.zza(this);
            }
        }
    }
}
