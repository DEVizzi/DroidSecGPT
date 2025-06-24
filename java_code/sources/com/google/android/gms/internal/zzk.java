package com.google.android.gms.internal;

import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.text.TextUtils;
import com.google.android.gms.internal.zzb;
import com.google.android.gms.internal.zzm;
import com.google.android.gms.internal.zzs;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.Map;
/* loaded from: classes.dex */
public abstract class zzk<T> implements Comparable<zzk<T>> {
    private final zzs.zza zzD;
    private final int zzE;
    private final String zzF;
    private final int zzG;
    private final zzm.zza zzH;
    private Integer zzI;
    private zzl zzJ;
    private boolean zzK;
    private boolean zzL;
    private boolean zzM;
    private long zzN;
    private zzo zzO;
    private zzb.zza zzP;

    /* loaded from: classes.dex */
    public enum zza {
        LOW,
        NORMAL,
        HIGH,
        IMMEDIATE
    }

    public zzk(int i, String str, zzm.zza zzaVar) {
        this.zzD = zzs.zza.zzak ? new zzs.zza() : null;
        this.zzK = true;
        this.zzL = false;
        this.zzM = false;
        this.zzN = 0L;
        this.zzP = null;
        this.zzE = i;
        this.zzF = str;
        this.zzH = zzaVar;
        zza((zzo) new zzd());
        this.zzG = zzb(str);
    }

    private byte[] zza(Map<String, String> map, String str) {
        StringBuilder sb = new StringBuilder();
        try {
            for (Map.Entry<String, String> entry : map.entrySet()) {
                sb.append(URLEncoder.encode(entry.getKey(), str));
                sb.append('=');
                sb.append(URLEncoder.encode(entry.getValue(), str));
                sb.append('&');
            }
            return sb.toString().getBytes(str);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Encoding not supported: " + str, e);
        }
    }

    private static int zzb(String str) {
        Uri parse;
        String host;
        if (TextUtils.isEmpty(str) || (parse = Uri.parse(str)) == null || (host = parse.getHost()) == null) {
            return 0;
        }
        return host.hashCode();
    }

    public Map<String, String> getHeaders() throws com.google.android.gms.internal.zza {
        return Collections.emptyMap();
    }

    public int getMethod() {
        return this.zzE;
    }

    public String getUrl() {
        return this.zzF;
    }

    public boolean isCanceled() {
        return this.zzL;
    }

    public String toString() {
        return (this.zzL ? "[X] " : "[ ] ") + getUrl() + " " + ("0x" + Integer.toHexString(zzg())) + " " + zzs() + " " + this.zzI;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final zzk<?> zza(int i) {
        this.zzI = Integer.valueOf(i);
        return this;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public zzk<?> zza(zzb.zza zzaVar) {
        this.zzP = zzaVar;
        return this;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public zzk<?> zza(zzl zzlVar) {
        this.zzJ = zzlVar;
        return this;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public zzk<?> zza(zzo zzoVar) {
        this.zzO = zzoVar;
        return this;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public abstract zzm<T> zza(zzi zziVar);

    /* JADX INFO: Access modifiers changed from: protected */
    public abstract void zza(T t);

    /* JADX INFO: Access modifiers changed from: protected */
    public zzr zzb(zzr zzrVar) {
        return zzrVar;
    }

    @Override // java.lang.Comparable
    /* renamed from: zzc */
    public int compareTo(zzk<T> zzkVar) {
        zza zzs = zzs();
        zza zzs2 = zzkVar.zzs();
        return zzs == zzs2 ? this.zzI.intValue() - zzkVar.zzI.intValue() : zzs2.ordinal() - zzs.ordinal();
    }

    public void zzc(zzr zzrVar) {
        if (this.zzH != null) {
            this.zzH.zze(zzrVar);
        }
    }

    public void zzc(String str) {
        if (zzs.zza.zzak) {
            this.zzD.zza(str, Thread.currentThread().getId());
        } else if (this.zzN == 0) {
            this.zzN = SystemClock.elapsedRealtime();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zzd(final String str) {
        if (this.zzJ != null) {
            this.zzJ.zzf(this);
        }
        if (!zzs.zza.zzak) {
            long elapsedRealtime = SystemClock.elapsedRealtime() - this.zzN;
            if (elapsedRealtime >= 3000) {
                zzs.zzb("%d ms: %s", Long.valueOf(elapsedRealtime), toString());
                return;
            }
            return;
        }
        final long id = Thread.currentThread().getId();
        if (Looper.myLooper() != Looper.getMainLooper()) {
            new Handler(Looper.getMainLooper()).post(new Runnable() { // from class: com.google.android.gms.internal.zzk.1
                @Override // java.lang.Runnable
                public void run() {
                    zzk.this.zzD.zza(str, id);
                    zzk.this.zzD.zzd(toString());
                }
            });
            return;
        }
        this.zzD.zza(str, id);
        this.zzD.zzd(toString());
    }

    public int zzg() {
        return this.zzG;
    }

    public String zzh() {
        return getUrl();
    }

    public zzb.zza zzi() {
        return this.zzP;
    }

    @Deprecated
    protected Map<String, String> zzj() throws com.google.android.gms.internal.zza {
        return zzn();
    }

    @Deprecated
    protected String zzk() {
        return zzo();
    }

    @Deprecated
    public String zzl() {
        return zzp();
    }

    @Deprecated
    public byte[] zzm() throws com.google.android.gms.internal.zza {
        Map<String, String> zzj = zzj();
        if (zzj == null || zzj.size() <= 0) {
            return null;
        }
        return zza(zzj, zzk());
    }

    protected Map<String, String> zzn() throws com.google.android.gms.internal.zza {
        return null;
    }

    protected String zzo() {
        return "UTF-8";
    }

    public String zzp() {
        return "application/x-www-form-urlencoded; charset=" + zzo();
    }

    public byte[] zzq() throws com.google.android.gms.internal.zza {
        Map<String, String> zzn = zzn();
        if (zzn == null || zzn.size() <= 0) {
            return null;
        }
        return zza(zzn, zzo());
    }

    public final boolean zzr() {
        return this.zzK;
    }

    public zza zzs() {
        return zza.NORMAL;
    }

    public final int zzt() {
        return this.zzO.zzd();
    }

    public zzo zzu() {
        return this.zzO;
    }

    public void zzv() {
        this.zzM = true;
    }

    public boolean zzw() {
        return this.zzM;
    }
}
