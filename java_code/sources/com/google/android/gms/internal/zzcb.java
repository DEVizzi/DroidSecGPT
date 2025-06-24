package com.google.android.gms.internal;

import android.content.Context;
import android.net.Uri;
import android.os.Environment;
import android.text.TextUtils;
import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
/* loaded from: classes.dex */
public class zzcb {
    private final Context mContext;
    private final String zzqr;
    private int zzuA;
    private int zzuB;
    private int zzuC;
    private String zzuD;
    private BlockingQueue<zzce> zzuF;
    private ExecutorService zzuG;
    private LinkedHashMap<String, String> zzuH = new LinkedHashMap<>();
    private AtomicBoolean zzuI;
    private File zzuJ;
    private int zzuz;

    public zzcb(Context context, String str, String str2, int i, int i2, int i3, int i4, Map<String, String> map, int i5) {
        File externalStorageDirectory;
        this.mContext = context;
        this.zzqr = str;
        this.zzuD = str2;
        this.zzuA = i;
        this.zzuB = i2;
        this.zzuC = i3;
        zzq(i4);
        this.zzuI = new AtomicBoolean(false);
        this.zzuI.set(zzbz.zzub.get().booleanValue());
        if (this.zzuI.get() && (externalStorageDirectory = Environment.getExternalStorageDirectory()) != null) {
            this.zzuJ = new File(externalStorageDirectory, "sdk_csi_data.txt");
        }
        for (Map.Entry<String, String> entry : map.entrySet()) {
            zzd(entry.getKey(), entry.getValue());
        }
        if (i5 == 1) {
            zzdj();
        }
        if (i5 == 2) {
            zzdk();
        }
        init();
    }

    private void init() {
        this.zzuF = new ArrayBlockingQueue(this.zzuA);
        this.zzuG = Executors.newSingleThreadExecutor();
        this.zzuG.execute(new Runnable() { // from class: com.google.android.gms.internal.zzcb.1
            @Override // java.lang.Runnable
            public void run() {
                zzcb.this.zzdl();
            }
        });
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:38:0x003a A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r1v6, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r1v9, types: [java.lang.String] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void zza(java.io.File r4, java.lang.String r5) {
        /*
            r3 = this;
            if (r4 == 0) goto L45
            r2 = 0
            java.io.FileOutputStream r1 = new java.io.FileOutputStream     // Catch: java.io.IOException -> L22 java.lang.Throwable -> L36
            r0 = 1
            r1.<init>(r4, r0)     // Catch: java.io.IOException -> L22 java.lang.Throwable -> L36
            byte[] r0 = r5.getBytes()     // Catch: java.lang.Throwable -> L4b java.io.IOException -> L4d
            r1.write(r0)     // Catch: java.lang.Throwable -> L4b java.io.IOException -> L4d
            r0 = 10
            r1.write(r0)     // Catch: java.lang.Throwable -> L4b java.io.IOException -> L4d
            if (r1 == 0) goto L1a
            r1.close()     // Catch: java.io.IOException -> L1b
        L1a:
            return
        L1b:
            r0 = move-exception
            java.lang.String r1 = "CsiReporter: Cannot close file: sdk_csi_data.txt."
            com.google.android.gms.ads.internal.util.client.zzb.zzd(r1, r0)
            goto L1a
        L22:
            r0 = move-exception
            r1 = r2
        L24:
            java.lang.String r2 = "CsiReporter: Cannot write to file: sdk_csi_data.txt."
            com.google.android.gms.ads.internal.util.client.zzb.zzd(r2, r0)     // Catch: java.lang.Throwable -> L4b
            if (r1 == 0) goto L1a
            r1.close()     // Catch: java.io.IOException -> L2f
            goto L1a
        L2f:
            r0 = move-exception
            java.lang.String r1 = "CsiReporter: Cannot close file: sdk_csi_data.txt."
            com.google.android.gms.ads.internal.util.client.zzb.zzd(r1, r0)
            goto L1a
        L36:
            r0 = move-exception
            r1 = r2
        L38:
            if (r1 == 0) goto L3d
            r1.close()     // Catch: java.io.IOException -> L3e
        L3d:
            throw r0
        L3e:
            r1 = move-exception
            java.lang.String r2 = "CsiReporter: Cannot close file: sdk_csi_data.txt."
            com.google.android.gms.ads.internal.util.client.zzb.zzd(r2, r1)
            goto L3d
        L45:
            java.lang.String r0 = "CsiReporter: File doesn't exists. Cannot write CSI data to file."
            com.google.android.gms.ads.internal.util.client.zzb.zzaC(r0)
            goto L1a
        L4b:
            r0 = move-exception
            goto L38
        L4d:
            r0 = move-exception
            goto L24
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.zzcb.zza(java.io.File, java.lang.String):void");
    }

    private void zzb(List<String> list) {
        if (list == null || list.isEmpty()) {
            return;
        }
        zzd("eid", TextUtils.join(",", list));
    }

    private boolean zzc(Map<String, String> map) {
        boolean z = false;
        for (int i = 0; !z && i < this.zzuB; i++) {
            try {
                Thread.sleep(this.zzuC);
                String zza = zza(this.zzuD, map);
                if (this.zzuI.get()) {
                    zza(this.zzuJ, zza);
                } else {
                    com.google.android.gms.ads.internal.zzo.zzbv().zzc(this.mContext, this.zzqr, zza);
                }
                z = true;
            } catch (InterruptedException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzd("CsiReporter: interrupted in sendReport()", e);
                Thread.currentThread().interrupt();
            }
        }
        return z;
    }

    private void zzdj() {
        zzb(zzbz.zzdb());
    }

    private void zzdk() {
        zzb(zzbz.zzx(this.mContext));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zzdl() {
        while (true) {
            try {
                List<zzce> zzp = zzp(this.zzuz);
                if (zzp != null) {
                    for (Map<String, String> map : zzc(zzp).values()) {
                        zzc(map);
                    }
                }
            } catch (InterruptedException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzd("CsiReporter:reporter interrupted", e);
                return;
            }
        }
    }

    private List<zzce> zzp(int i) throws InterruptedException {
        ArrayList arrayList = new ArrayList();
        for (int i2 = 0; i2 < i; i2++) {
            arrayList.add(this.zzuF.take());
        }
        return arrayList;
    }

    private void zzq(int i) {
        if (i < 1) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("CsiReporter - too small batch size :" + i + ", changed to 1");
            i = 1;
        }
        if (i > this.zzuA) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("CsiReporter - batch size :" + i + " bigger than buffer size, change to buffer limit");
            i = this.zzuA;
        }
        this.zzuz = i;
    }

    String zza(String str, Map<String, String> map) {
        Uri.Builder buildUpon = Uri.parse(str).buildUpon();
        for (Map.Entry<String, String> entry : map.entrySet()) {
            buildUpon.appendQueryParameter(entry.getKey(), entry.getValue());
        }
        return buildUpon.build().toString();
    }

    public boolean zza(zzce zzceVar) {
        return this.zzuF.offer(zzceVar);
    }

    Map<String, Map<String, String>> zzc(List<zzce> list) {
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        for (zzce zzceVar : list) {
            String zzdr = zzceVar.zzdr();
            if (linkedHashMap.containsKey(zzdr)) {
                ((List) linkedHashMap.get(zzdr)).add(zzceVar);
            } else {
                ArrayList arrayList = new ArrayList();
                arrayList.add(zzceVar);
                linkedHashMap.put(zzdr, arrayList);
            }
        }
        LinkedHashMap linkedHashMap2 = new LinkedHashMap();
        for (Map.Entry entry : linkedHashMap.entrySet()) {
            List list2 = (List) entry.getValue();
            LinkedHashMap linkedHashMap3 = new LinkedHashMap(this.zzuH);
            try {
                linkedHashMap3.putAll(zzce.zza((zzce[]) list2.toArray(new zzce[list2.size()])));
                linkedHashMap2.put(entry.getKey(), linkedHashMap3);
            } catch (IllegalArgumentException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzd("CsiReporter:failed to merge tickers:" + list2, e);
            }
        }
        return linkedHashMap2;
    }

    void zzd(String str, String str2) {
        this.zzuH.put(str, str2);
    }
}
