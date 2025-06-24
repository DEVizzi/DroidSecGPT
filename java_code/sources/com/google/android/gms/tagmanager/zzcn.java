package com.google.android.gms.tagmanager;

import android.content.Context;
import android.content.res.Resources;
import com.google.android.gms.internal.zzaf;
import com.google.android.gms.internal.zzpx;
import com.google.android.gms.internal.zzqf;
import com.google.android.gms.internal.zzrm;
import com.google.android.gms.internal.zzrn;
import com.google.android.gms.tagmanager.zzp;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.json.JSONException;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zzcn implements zzp.zzf {
    private final Context mContext;
    private final String zzaKy;
    private zzbf<zzpx.zza> zzaMU;
    private final ExecutorService zzaNb = Executors.newSingleThreadExecutor();

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzcn(Context context, String str) {
        this.mContext = context;
        this.zzaKy = str;
    }

    private zzqf.zzc zza(ByteArrayOutputStream byteArrayOutputStream) {
        try {
            return zzaz.zzey(byteArrayOutputStream.toString("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            zzbg.zzay("Failed to convert binary resource to string for JSON parsing; the file format is not UTF-8 format.");
            return null;
        } catch (JSONException e2) {
            zzbg.zzaC("Failed to extract the container from the resource file. Resource is a UTF-8 encoded string but doesn't contain a JSON container");
            return null;
        }
    }

    private void zzd(zzpx.zza zzaVar) throws IllegalArgumentException {
        if (zzaVar.zziO == null && zzaVar.zzaPa == null) {
            throw new IllegalArgumentException("Resource and SupplementedResource are NULL.");
        }
    }

    private zzqf.zzc zzr(byte[] bArr) {
        try {
            zzqf.zzc zzb = zzqf.zzb(zzaf.zzf.zzc(bArr));
            if (zzb != null) {
                zzbg.zzaB("The container was successfully loaded from the resource (using binary file)");
                return zzb;
            }
            return zzb;
        } catch (zzqf.zzg e) {
            zzbg.zzaC("The resource file is invalid. The container from the binary file is invalid");
            return null;
        } catch (zzrm e2) {
            zzbg.zzaz("The resource file is corrupted. The container cannot be extracted from the binary file");
            return null;
        }
    }

    @Override // com.google.android.gms.common.api.Releasable
    public synchronized void release() {
        this.zzaNb.shutdown();
    }

    @Override // com.google.android.gms.tagmanager.zzp.zzf
    public void zza(zzbf<zzpx.zza> zzbfVar) {
        this.zzaMU = zzbfVar;
    }

    @Override // com.google.android.gms.tagmanager.zzp.zzf
    public void zzb(final zzpx.zza zzaVar) {
        this.zzaNb.execute(new Runnable() { // from class: com.google.android.gms.tagmanager.zzcn.2
            @Override // java.lang.Runnable
            public void run() {
                zzcn.this.zzc(zzaVar);
            }
        });
    }

    boolean zzc(zzpx.zza zzaVar) {
        boolean z = false;
        File zzzo = zzzo();
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(zzzo);
            try {
                try {
                    fileOutputStream.write(zzrn.zzf(zzaVar));
                    z = true;
                } catch (IOException e) {
                    zzbg.zzaC("Error writing resource to disk. Removing resource from disk.");
                    zzzo.delete();
                    try {
                        fileOutputStream.close();
                    } catch (IOException e2) {
                        zzbg.zzaC("error closing stream for writing resource to disk");
                    }
                }
            } finally {
                try {
                    fileOutputStream.close();
                } catch (IOException e3) {
                    zzbg.zzaC("error closing stream for writing resource to disk");
                }
            }
        } catch (FileNotFoundException e4) {
            zzbg.zzaz("Error opening resource file for writing");
        }
        return z;
    }

    @Override // com.google.android.gms.tagmanager.zzp.zzf
    public zzqf.zzc zziR(int i) {
        try {
            InputStream openRawResource = this.mContext.getResources().openRawResource(i);
            zzbg.zzaB("Attempting to load a container from the resource ID " + i + " (" + this.mContext.getResources().getResourceName(i) + ")");
            try {
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                zzqf.zzc(openRawResource, byteArrayOutputStream);
                zzqf.zzc zza = zza(byteArrayOutputStream);
                if (zza != null) {
                    zzbg.zzaB("The container was successfully loaded from the resource (using JSON file format)");
                } else {
                    zza = zzr(byteArrayOutputStream.toByteArray());
                }
                return zza;
            } catch (IOException e) {
                zzbg.zzaC("Error reading the default container with resource ID " + i + " (" + this.mContext.getResources().getResourceName(i) + ")");
                return null;
            }
        } catch (Resources.NotFoundException e2) {
            zzbg.zzaC("Failed to load the container. No default container resource found with the resource ID " + i);
            return null;
        }
    }

    @Override // com.google.android.gms.tagmanager.zzp.zzf
    public void zzyw() {
        this.zzaNb.execute(new Runnable() { // from class: com.google.android.gms.tagmanager.zzcn.1
            @Override // java.lang.Runnable
            public void run() {
                zzcn.this.zzzn();
            }
        });
    }

    /* JADX WARN: Code restructure failed: missing block: B:9:0x002c, code lost:
        if (r0 == r1) goto L48;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    void zzzn() {
        /*
            r3 = this;
            com.google.android.gms.tagmanager.zzbf<com.google.android.gms.internal.zzpx$zza> r0 = r3.zzaMU
            if (r0 != 0) goto Lc
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "Callback must be set before execute"
            r0.<init>(r1)
            throw r0
        Lc:
            com.google.android.gms.tagmanager.zzbf<com.google.android.gms.internal.zzpx$zza> r0 = r3.zzaMU
            r0.zzyv()
            java.lang.String r0 = "Attempting to load resource from disk"
            com.google.android.gms.tagmanager.zzbg.zzaB(r0)
            com.google.android.gms.tagmanager.zzcb r0 = com.google.android.gms.tagmanager.zzcb.zzzf()
            com.google.android.gms.tagmanager.zzcb$zza r0 = r0.zzzg()
            com.google.android.gms.tagmanager.zzcb$zza r1 = com.google.android.gms.tagmanager.zzcb.zza.CONTAINER
            if (r0 == r1) goto L2e
            com.google.android.gms.tagmanager.zzcb r0 = com.google.android.gms.tagmanager.zzcb.zzzf()
            com.google.android.gms.tagmanager.zzcb$zza r0 = r0.zzzg()
            com.google.android.gms.tagmanager.zzcb$zza r1 = com.google.android.gms.tagmanager.zzcb.zza.CONTAINER_DEBUG
            if (r0 != r1) goto L46
        L2e:
            java.lang.String r0 = r3.zzaKy
            com.google.android.gms.tagmanager.zzcb r1 = com.google.android.gms.tagmanager.zzcb.zzzf()
            java.lang.String r1 = r1.getContainerId()
            boolean r0 = r0.equals(r1)
            if (r0 == 0) goto L46
            com.google.android.gms.tagmanager.zzbf<com.google.android.gms.internal.zzpx$zza> r0 = r3.zzaMU
            com.google.android.gms.tagmanager.zzbf$zza r1 = com.google.android.gms.tagmanager.zzbf.zza.NOT_AVAILABLE
            r0.zza(r1)
        L45:
            return
        L46:
            java.io.FileInputStream r1 = new java.io.FileInputStream     // Catch: java.io.FileNotFoundException -> L70
            java.io.File r0 = r3.zzzo()     // Catch: java.io.FileNotFoundException -> L70
            r1.<init>(r0)     // Catch: java.io.FileNotFoundException -> L70
            java.io.ByteArrayOutputStream r0 = new java.io.ByteArrayOutputStream     // Catch: java.io.IOException -> L85 java.lang.IllegalArgumentException -> L9d java.lang.Throwable -> Lb5
            r0.<init>()     // Catch: java.io.IOException -> L85 java.lang.IllegalArgumentException -> L9d java.lang.Throwable -> Lb5
            com.google.android.gms.internal.zzqf.zzc(r1, r0)     // Catch: java.io.IOException -> L85 java.lang.IllegalArgumentException -> L9d java.lang.Throwable -> Lb5
            byte[] r0 = r0.toByteArray()     // Catch: java.io.IOException -> L85 java.lang.IllegalArgumentException -> L9d java.lang.Throwable -> Lb5
            com.google.android.gms.internal.zzpx$zza r0 = com.google.android.gms.internal.zzpx.zza.zzs(r0)     // Catch: java.io.IOException -> L85 java.lang.IllegalArgumentException -> L9d java.lang.Throwable -> Lb5
            r3.zzd(r0)     // Catch: java.io.IOException -> L85 java.lang.IllegalArgumentException -> L9d java.lang.Throwable -> Lb5
            com.google.android.gms.tagmanager.zzbf<com.google.android.gms.internal.zzpx$zza> r2 = r3.zzaMU     // Catch: java.io.IOException -> L85 java.lang.IllegalArgumentException -> L9d java.lang.Throwable -> Lb5
            r2.zzz(r0)     // Catch: java.io.IOException -> L85 java.lang.IllegalArgumentException -> L9d java.lang.Throwable -> Lb5
            r1.close()     // Catch: java.io.IOException -> L7e
        L6a:
            java.lang.String r0 = "The Disk resource was successfully read."
            com.google.android.gms.tagmanager.zzbg.zzaB(r0)
            goto L45
        L70:
            r0 = move-exception
            java.lang.String r0 = "Failed to find the resource in the disk"
            com.google.android.gms.tagmanager.zzbg.zzay(r0)
            com.google.android.gms.tagmanager.zzbf<com.google.android.gms.internal.zzpx$zza> r0 = r3.zzaMU
            com.google.android.gms.tagmanager.zzbf$zza r1 = com.google.android.gms.tagmanager.zzbf.zza.NOT_AVAILABLE
            r0.zza(r1)
            goto L45
        L7e:
            r0 = move-exception
            java.lang.String r0 = "Error closing stream for reading resource from disk"
            com.google.android.gms.tagmanager.zzbg.zzaC(r0)
            goto L6a
        L85:
            r0 = move-exception
            com.google.android.gms.tagmanager.zzbf<com.google.android.gms.internal.zzpx$zza> r0 = r3.zzaMU     // Catch: java.lang.Throwable -> Lb5
            com.google.android.gms.tagmanager.zzbf$zza r2 = com.google.android.gms.tagmanager.zzbf.zza.IO_ERROR     // Catch: java.lang.Throwable -> Lb5
            r0.zza(r2)     // Catch: java.lang.Throwable -> Lb5
            java.lang.String r0 = "Failed to read the resource from disk"
            com.google.android.gms.tagmanager.zzbg.zzaC(r0)     // Catch: java.lang.Throwable -> Lb5
            r1.close()     // Catch: java.io.IOException -> L96
            goto L6a
        L96:
            r0 = move-exception
            java.lang.String r0 = "Error closing stream for reading resource from disk"
            com.google.android.gms.tagmanager.zzbg.zzaC(r0)
            goto L6a
        L9d:
            r0 = move-exception
            com.google.android.gms.tagmanager.zzbf<com.google.android.gms.internal.zzpx$zza> r0 = r3.zzaMU     // Catch: java.lang.Throwable -> Lb5
            com.google.android.gms.tagmanager.zzbf$zza r2 = com.google.android.gms.tagmanager.zzbf.zza.IO_ERROR     // Catch: java.lang.Throwable -> Lb5
            r0.zza(r2)     // Catch: java.lang.Throwable -> Lb5
            java.lang.String r0 = "Failed to read the resource from disk. The resource is inconsistent"
            com.google.android.gms.tagmanager.zzbg.zzaC(r0)     // Catch: java.lang.Throwable -> Lb5
            r1.close()     // Catch: java.io.IOException -> Lae
            goto L6a
        Lae:
            r0 = move-exception
            java.lang.String r0 = "Error closing stream for reading resource from disk"
            com.google.android.gms.tagmanager.zzbg.zzaC(r0)
            goto L6a
        Lb5:
            r0 = move-exception
            r1.close()     // Catch: java.io.IOException -> Lba
        Lb9:
            throw r0
        Lba:
            r1 = move-exception
            java.lang.String r1 = "Error closing stream for reading resource from disk"
            com.google.android.gms.tagmanager.zzbg.zzaC(r1)
            goto Lb9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.tagmanager.zzcn.zzzn():void");
    }

    File zzzo() {
        return new File(this.mContext.getDir("google_tagmanager", 0), "resource_" + this.zzaKy);
    }
}
