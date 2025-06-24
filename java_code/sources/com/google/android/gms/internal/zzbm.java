package com.google.android.gms.internal;

import android.util.Base64OutputStream;
import com.google.android.gms.internal.zzbp;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Iterator;
import java.util.Locale;
import java.util.PriorityQueue;
/* loaded from: classes.dex */
public class zzbm {
    private final int zzrM;
    private final zzbl zzrO = new zzbo();
    private final int zzrL = 6;
    private final int zzrN = 0;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class zza {
        ByteArrayOutputStream zzrQ = new ByteArrayOutputStream(4096);
        Base64OutputStream zzrR = new Base64OutputStream(this.zzrQ, 10);

        /* JADX WARN: Type inference failed for: r2v0, types: [java.io.ByteArrayOutputStream, android.util.Base64OutputStream] */
        public String toString() {
            String str;
            try {
                this.zzrR.close();
            } catch (IOException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzb("HashManager: Unable to convert to Base64.", e);
            }
            try {
                this.zzrQ.close();
                str = this.zzrQ.toString();
            } catch (IOException e2) {
                com.google.android.gms.ads.internal.util.client.zzb.zzb("HashManager: Unable to convert to Base64.", e2);
                str = "";
            } finally {
                this.zzrQ = null;
                this.zzrR = null;
            }
            return str;
        }

        public void write(byte[] data) throws IOException {
            this.zzrR.write(data);
        }
    }

    public zzbm(int i) {
        this.zzrM = i;
    }

    private String zzz(String str) {
        String[] split = str.split("\n");
        if (split.length == 0) {
            return "";
        }
        zza zzcv = zzcv();
        Arrays.sort(split, new Comparator<String>() { // from class: com.google.android.gms.internal.zzbm.1
            @Override // java.util.Comparator
            public int compare(String s1, String s2) {
                return s2.length() - s1.length();
            }
        });
        for (int i = 0; i < split.length && i < this.zzrM; i++) {
            if (split[i].trim().length() != 0) {
                try {
                    zzcv.write(this.zzrO.zzy(split[i]));
                } catch (IOException e) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzb("Error while writing hash to byteStream", e);
                }
            }
        }
        return zzcv.toString();
    }

    String zzA(String str) {
        String[] split = str.split("\n");
        if (split.length == 0) {
            return "";
        }
        zza zzcv = zzcv();
        PriorityQueue priorityQueue = new PriorityQueue(this.zzrM, new Comparator<zzbp.zza>() { // from class: com.google.android.gms.internal.zzbm.2
            @Override // java.util.Comparator
            /* renamed from: zza */
            public int compare(zzbp.zza zzaVar, zzbp.zza zzaVar2) {
                return (int) (zzaVar.value - zzaVar2.value);
            }
        });
        for (String str2 : split) {
            String[] zzC = zzbn.zzC(str2);
            if (zzC.length >= this.zzrL) {
                zzbp.zza(zzC, this.zzrM, this.zzrL, priorityQueue);
            }
        }
        Iterator it = priorityQueue.iterator();
        while (it.hasNext()) {
            try {
                zzcv.write(this.zzrO.zzy(((zzbp.zza) it.next()).zzrT));
            } catch (IOException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzb("Error while writing hash to byteStream", e);
            }
        }
        return zzcv.toString();
    }

    public String zza(ArrayList<String> arrayList) {
        StringBuffer stringBuffer = new StringBuffer();
        Iterator<String> it = arrayList.iterator();
        while (it.hasNext()) {
            stringBuffer.append(it.next().toLowerCase(Locale.US));
            stringBuffer.append('\n');
        }
        switch (this.zzrN) {
            case 0:
                return zzA(stringBuffer.toString());
            case 1:
                return zzz(stringBuffer.toString());
            default:
                return "";
        }
    }

    zza zzcv() {
        return new zza();
    }
}
