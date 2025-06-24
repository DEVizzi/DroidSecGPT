package com.google.android.gms.analytics.internal;

import android.content.Context;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
/* loaded from: classes.dex */
public class zzn extends zzd {
    private volatile String zzJd;
    private Future<String> zzKG;

    /* JADX INFO: Access modifiers changed from: protected */
    public zzn(zzf zzfVar) {
        super(zzfVar);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v2, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r2v4, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r2v9, types: [java.lang.String] */
    private boolean zzg(Context context, String str) {
        boolean z = false;
        com.google.android.gms.common.internal.zzu.zzcj(str);
        com.google.android.gms.common.internal.zzu.zzbZ("ClientId should be saved from worker thread");
        FileOutputStream fileOutputStream = null;
        fileOutputStream = null;
        fileOutputStream = null;
        try {
            try {
                try {
                    zza("Storing clientId", str);
                    fileOutputStream = context.openFileOutput("gaClientId", 0);
                    fileOutputStream.write(str.getBytes());
                    z = true;
                    fileOutputStream = fileOutputStream;
                    if (fileOutputStream != null) {
                        try {
                            fileOutputStream.close();
                            fileOutputStream = fileOutputStream;
                        } catch (IOException e) {
                            zze("Failed to close clientId writing stream", e);
                            fileOutputStream = "Failed to close clientId writing stream";
                        }
                    }
                } catch (Throwable th) {
                    if (fileOutputStream != null) {
                        try {
                            fileOutputStream.close();
                        } catch (IOException e2) {
                            zze("Failed to close clientId writing stream", e2);
                        }
                    }
                    throw th;
                }
            } catch (IOException e3) {
                zze("Error writing to clientId file", e3);
                fileOutputStream = fileOutputStream;
                if (fileOutputStream != null) {
                    try {
                        fileOutputStream.close();
                        fileOutputStream = fileOutputStream;
                    } catch (IOException e4) {
                        zze("Failed to close clientId writing stream", e4);
                        fileOutputStream = "Failed to close clientId writing stream";
                    }
                }
            }
        } catch (FileNotFoundException e5) {
            zze("Error creating clientId file", e5);
            fileOutputStream = fileOutputStream;
            if (fileOutputStream != null) {
                try {
                    fileOutputStream.close();
                    fileOutputStream = fileOutputStream;
                } catch (IOException e6) {
                    zze("Failed to close clientId writing stream", e6);
                    fileOutputStream = "Failed to close clientId writing stream";
                }
            }
        }
        return z;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String zziS() {
        String zziT = zziT();
        try {
            return !zzg(zzhS().getContext(), zziT) ? "0" : zziT;
        } catch (Exception e) {
            zze("Error saving clientId file", e);
            return "0";
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:57:0x0074 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:59:0x008d A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:61:0x009d A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r2v12, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r2v14, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r2v15, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r2v6, types: [java.lang.String] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:37:0x008b -> B:63:0x002e). Please submit an issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:38:0x008d -> B:63:0x002e). Please submit an issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:41:0x0092 -> B:63:0x002e). Please submit an issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    protected java.lang.String zzX(android.content.Context r7) {
        /*
            r6 = this;
            r0 = 0
            java.lang.String r1 = "ClientId should be loaded from worker thread"
            com.google.android.gms.common.internal.zzu.zzbZ(r1)
            java.lang.String r1 = "gaClientId"
            java.io.FileInputStream r2 = r7.openFileInput(r1)     // Catch: java.io.FileNotFoundException -> L70 java.io.IOException -> L7f java.lang.Throwable -> L98
            r1 = 36
            byte[] r3 = new byte[r1]     // Catch: java.lang.Throwable -> La8 java.io.IOException -> Laa java.io.FileNotFoundException -> Lac
            r1 = 0
            int r4 = r3.length     // Catch: java.lang.Throwable -> La8 java.io.IOException -> Laa java.io.FileNotFoundException -> Lac
            int r4 = r2.read(r3, r1, r4)     // Catch: java.lang.Throwable -> La8 java.io.IOException -> Laa java.io.FileNotFoundException -> Lac
            int r1 = r2.available()     // Catch: java.lang.Throwable -> La8 java.io.IOException -> Laa java.io.FileNotFoundException -> Lac
            if (r1 <= 0) goto L36
            java.lang.String r1 = "clientId file seems corrupted, deleting it."
            r6.zzaW(r1)     // Catch: java.lang.Throwable -> La8 java.io.IOException -> Laa java.io.FileNotFoundException -> Lac
            r2.close()     // Catch: java.lang.Throwable -> La8 java.io.IOException -> Laa java.io.FileNotFoundException -> Lac
            java.lang.String r1 = "gaClientId"
            r7.deleteFile(r1)     // Catch: java.lang.Throwable -> La8 java.io.IOException -> Laa java.io.FileNotFoundException -> Lac
            if (r2 == 0) goto L2e
            r2.close()     // Catch: java.io.IOException -> L2f
        L2e:
            return r0
        L2f:
            r1 = move-exception
            java.lang.String r2 = "Failed to close client id reading stream"
            r6.zze(r2, r1)
            goto L2e
        L36:
            r1 = 14
            if (r4 >= r1) goto L54
            java.lang.String r1 = "clientId file is empty, deleting it."
            r6.zzaW(r1)     // Catch: java.lang.Throwable -> La8 java.io.IOException -> Laa java.io.FileNotFoundException -> Lac
            r2.close()     // Catch: java.lang.Throwable -> La8 java.io.IOException -> Laa java.io.FileNotFoundException -> Lac
            java.lang.String r1 = "gaClientId"
            r7.deleteFile(r1)     // Catch: java.lang.Throwable -> La8 java.io.IOException -> Laa java.io.FileNotFoundException -> Lac
            if (r2 == 0) goto L2e
            r2.close()     // Catch: java.io.IOException -> L4d
            goto L2e
        L4d:
            r1 = move-exception
            java.lang.String r2 = "Failed to close client id reading stream"
            r6.zze(r2, r1)
            goto L2e
        L54:
            r2.close()     // Catch: java.lang.Throwable -> La8 java.io.IOException -> Laa java.io.FileNotFoundException -> Lac
            java.lang.String r1 = new java.lang.String     // Catch: java.lang.Throwable -> La8 java.io.IOException -> Laa java.io.FileNotFoundException -> Lac
            r5 = 0
            r1.<init>(r3, r5, r4)     // Catch: java.lang.Throwable -> La8 java.io.IOException -> Laa java.io.FileNotFoundException -> Lac
            java.lang.String r3 = "Read client id from disk"
            r6.zza(r3, r1)     // Catch: java.lang.Throwable -> La8 java.io.IOException -> Laa java.io.FileNotFoundException -> Lac
            if (r2 == 0) goto L67
            r2.close()     // Catch: java.io.IOException -> L69
        L67:
            r0 = r1
            goto L2e
        L69:
            r0 = move-exception
            java.lang.String r2 = "Failed to close client id reading stream"
            r6.zze(r2, r0)
            goto L67
        L70:
            r1 = move-exception
            r1 = r0
        L72:
            if (r1 == 0) goto L2e
            r1.close()     // Catch: java.io.IOException -> L78
            goto L2e
        L78:
            r1 = move-exception
            java.lang.String r2 = "Failed to close client id reading stream"
            r6.zze(r2, r1)
            goto L2e
        L7f:
            r1 = move-exception
            r2 = r0
        L81:
            java.lang.String r3 = "Error reading client id file, deleting it"
            r6.zze(r3, r1)     // Catch: java.lang.Throwable -> La8
            java.lang.String r1 = "gaClientId"
            r7.deleteFile(r1)     // Catch: java.lang.Throwable -> La8
            if (r2 == 0) goto L2e
            r2.close()     // Catch: java.io.IOException -> L91
            goto L2e
        L91:
            r1 = move-exception
            java.lang.String r2 = "Failed to close client id reading stream"
            r6.zze(r2, r1)
            goto L2e
        L98:
            r1 = move-exception
            r2 = r0
            r0 = r1
        L9b:
            if (r2 == 0) goto La0
            r2.close()     // Catch: java.io.IOException -> La1
        La0:
            throw r0
        La1:
            r1 = move-exception
            java.lang.String r2 = "Failed to close client id reading stream"
            r6.zze(r2, r1)
            goto La0
        La8:
            r0 = move-exception
            goto L9b
        Laa:
            r1 = move-exception
            goto L81
        Lac:
            r1 = move-exception
            r1 = r2
            goto L72
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.analytics.internal.zzn.zzX(android.content.Context):java.lang.String");
    }

    @Override // com.google.android.gms.analytics.internal.zzd
    protected void zzhn() {
    }

    public String zziP() {
        String str;
        zzia();
        synchronized (this) {
            if (this.zzJd == null) {
                this.zzKG = zzhS().zzb(new Callable<String>() { // from class: com.google.android.gms.analytics.internal.zzn.1
                    @Override // java.util.concurrent.Callable
                    /* renamed from: zziU */
                    public String call() throws Exception {
                        return zzn.this.zziR();
                    }
                });
            }
            if (this.zzKG != null) {
                try {
                    this.zzJd = this.zzKG.get();
                } catch (InterruptedException e) {
                    zzd("ClientId loading or generation was interrupted", e);
                    this.zzJd = "0";
                } catch (ExecutionException e2) {
                    zze("Failed to load or generate client id", e2);
                    this.zzJd = "0";
                }
                if (this.zzJd == null) {
                    this.zzJd = "0";
                }
                zza("Loaded clientId", this.zzJd);
                this.zzKG = null;
            }
            str = this.zzJd;
        }
        return str;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String zziQ() {
        synchronized (this) {
            this.zzJd = null;
            this.zzKG = zzhS().zzb(new Callable<String>() { // from class: com.google.android.gms.analytics.internal.zzn.2
                @Override // java.util.concurrent.Callable
                /* renamed from: zziU */
                public String call() throws Exception {
                    return zzn.this.zziS();
                }
            });
        }
        return zziP();
    }

    String zziR() {
        String zzX = zzX(zzhS().getContext());
        return zzX == null ? zziS() : zzX;
    }

    protected String zziT() {
        return UUID.randomUUID().toString().toLowerCase();
    }
}
