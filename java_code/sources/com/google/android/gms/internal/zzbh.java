package com.google.android.gms.internal;

import java.util.ArrayList;
import java.util.Iterator;
@zzgd
/* loaded from: classes.dex */
public class zzbh {
    private final int zzrj;
    private final int zzrk;
    private final int zzrl;
    private final zzbm zzrm;
    private int zzrr;
    private final Object zzqt = new Object();
    private ArrayList<String> zzrn = new ArrayList<>();
    private int zzro = 0;
    private int zzrp = 0;
    private int zzrq = 0;
    private String zzrs = "";

    public zzbh(int i, int i2, int i3, int i4) {
        this.zzrj = i;
        this.zzrk = i2;
        this.zzrl = i3;
        this.zzrm = new zzbm(i4);
    }

    private String zza(ArrayList<String> arrayList, int i) {
        if (arrayList.isEmpty()) {
            return "";
        }
        StringBuffer stringBuffer = new StringBuffer();
        Iterator<String> it = arrayList.iterator();
        while (it.hasNext()) {
            stringBuffer.append(it.next());
            stringBuffer.append(' ');
            if (stringBuffer.length() > i) {
                break;
            }
        }
        stringBuffer.deleteCharAt(stringBuffer.length() - 1);
        String stringBuffer2 = stringBuffer.toString();
        return stringBuffer2.length() >= i ? stringBuffer2.substring(0, i) : stringBuffer2;
    }

    private void zzw(String str) {
        if (str == null || str.length() < this.zzrl) {
            return;
        }
        synchronized (this.zzqt) {
            this.zzrn.add(str);
            this.zzro += str.length();
        }
    }

    public boolean equals(Object obj) {
        if (obj instanceof zzbh) {
            if (obj == this) {
                return true;
            }
            zzbh zzbhVar = (zzbh) obj;
            return zzbhVar.zzci() != null && zzbhVar.zzci().equals(zzci());
        }
        return false;
    }

    public int getScore() {
        return this.zzrr;
    }

    public int hashCode() {
        return zzci().hashCode();
    }

    public String toString() {
        return "ActivityContent fetchId: " + this.zzrp + " score:" + this.zzrr + " total_length:" + this.zzro + "\n text: " + zza(this.zzrn, 200) + "\n signture: " + this.zzrs;
    }

    int zza(int i, int i2) {
        return (this.zzrj * i) + (this.zzrk * i2);
    }

    public boolean zzch() {
        boolean z;
        synchronized (this.zzqt) {
            z = this.zzrq == 0;
        }
        return z;
    }

    public String zzci() {
        return this.zzrs;
    }

    public void zzcj() {
        synchronized (this.zzqt) {
            this.zzrr -= 100;
        }
    }

    public void zzck() {
        synchronized (this.zzqt) {
            this.zzrq--;
        }
    }

    public void zzcl() {
        synchronized (this.zzqt) {
            this.zzrq++;
        }
    }

    public void zzcm() {
        synchronized (this.zzqt) {
            int zza = zza(this.zzro, this.zzrp);
            if (zza > this.zzrr) {
                this.zzrr = zza;
                this.zzrs = this.zzrm.zza(this.zzrn);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int zzcn() {
        return this.zzro;
    }

    public void zzg(int i) {
        this.zzrp = i;
    }

    public void zzu(String str) {
        zzw(str);
        synchronized (this.zzqt) {
            if (this.zzrq < 0) {
                com.google.android.gms.ads.internal.util.client.zzb.zzay("ActivityContent: negative number of WebViews.");
            }
            zzcm();
        }
    }

    public void zzv(String str) {
        zzw(str);
    }
}
