package com.google.android.gms.internal;

import android.support.v4.view.accessibility.AccessibilityEventCompat;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.text.DecimalFormat;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
@zzgd
/* loaded from: classes.dex */
public class zzdr {
    private static final Set<String> zzwF = Collections.synchronizedSet(new HashSet());
    private static final DecimalFormat zzwG = new DecimalFormat("#,###");
    private zzid zzoA;
    private File zzwH;
    private boolean zzwI;

    public zzdr(zzid zzidVar) {
        this.zzoA = zzidVar;
        File cacheDir = zzidVar.getContext().getCacheDir();
        if (cacheDir == null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Context.getCacheDir() returned null");
            return;
        }
        this.zzwH = new File(cacheDir, "admobVideoStreams");
        if (!this.zzwH.isDirectory() && !this.zzwH.mkdirs()) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Could not create preload cache directory at " + this.zzwH.getAbsolutePath());
            this.zzwH = null;
        } else if (this.zzwH.setReadable(true, false) && this.zzwH.setExecutable(true, false)) {
        } else {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Could not set cache file permissions at " + this.zzwH.getAbsolutePath());
            this.zzwH = null;
        }
    }

    private String zzX(String str) {
        return com.google.android.gms.ads.internal.client.zzk.zzcA().zzax(str);
    }

    private File zza(File file) {
        return new File(this.zzwH, file.getName() + ".done");
    }

    private void zza(final String str, final File file) {
        com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.internal.zzdr.3
            @Override // java.lang.Runnable
            public void run() {
                HashMap hashMap = new HashMap();
                hashMap.put("event", "precacheCanceled");
                hashMap.put("src", str);
                if (file != null) {
                    hashMap.put("cachedSrc", file.getAbsolutePath());
                }
                zzdr.this.zzoA.zzc("onPrecacheEvent", hashMap);
            }
        });
    }

    private void zza(final String str, final File file, final int i) {
        com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.internal.zzdr.2
            @Override // java.lang.Runnable
            public void run() {
                HashMap hashMap = new HashMap();
                hashMap.put("event", "precacheComplete");
                hashMap.put("src", str);
                hashMap.put("cachedSrc", file.getAbsolutePath());
                hashMap.put("totalBytes", Integer.toString(i));
                zzdr.this.zzoA.zzc("onPrecacheEvent", hashMap);
            }
        });
    }

    private void zza(final String str, final File file, final int i, final int i2) {
        com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.internal.zzdr.1
            @Override // java.lang.Runnable
            public void run() {
                HashMap hashMap = new HashMap();
                hashMap.put("event", "precacheProgress");
                hashMap.put("src", str);
                hashMap.put("cachedSrc", file.getAbsolutePath());
                hashMap.put("bytesLoaded", Integer.toString(i));
                hashMap.put("totalBytes", Integer.toString(i2));
                zzdr.this.zzoA.zzc("onPrecacheEvent", hashMap);
            }
        });
    }

    private static void zzb(File file) {
        if (file.isFile()) {
            file.setLastModified(System.currentTimeMillis());
            return;
        }
        try {
            file.createNewFile();
        } catch (IOException e) {
        }
    }

    public void abort() {
        this.zzwI = true;
    }

    public boolean zzW(String str) {
        FileOutputStream fileOutputStream;
        boolean z;
        int responseCode;
        if (this.zzwH == null) {
            zza(str, null);
            return false;
        }
        while (zzdQ() > zzbz.zztO.get().intValue()) {
            if (!zzdR()) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Unable to expire stream cache");
                zza(str, null);
                return false;
            }
        }
        File file = new File(this.zzwH, zzX(str));
        File zza = zza(file);
        if (file.isFile() && zza.isFile()) {
            com.google.android.gms.ads.internal.util.client.zzb.zzay("Stream cache hit at " + str);
            zza(str, file, (int) file.length());
            return true;
        }
        String str2 = this.zzwH.getAbsolutePath() + str;
        synchronized (zzwF) {
            if (zzwF.contains(str2)) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Stream cache already in progress at " + str);
                zza(str, file);
                z = false;
            } else {
                zzwF.add(str2);
                try {
                    URLConnection openConnection = new URL(str).openConnection();
                    int intValue = zzbz.zztS.get().intValue();
                    openConnection.setConnectTimeout(intValue);
                    openConnection.setReadTimeout(intValue);
                    if ((openConnection instanceof HttpURLConnection) && (responseCode = ((HttpURLConnection) openConnection).getResponseCode()) >= 400) {
                        throw new IOException("HTTP status code " + responseCode + " at " + str);
                    }
                    int contentLength = openConnection.getContentLength();
                    if (contentLength < 0) {
                        com.google.android.gms.ads.internal.util.client.zzb.zzaC("Stream cache aborted, missing content-length header at " + str);
                        zza(str, file);
                        zzwF.remove(str2);
                        z = false;
                    } else {
                        String format = zzwG.format(contentLength);
                        int intValue2 = zzbz.zztP.get().intValue();
                        if (contentLength > intValue2) {
                            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Content length " + format + " exceeds limit at " + str);
                            zza(str, file);
                            zzwF.remove(str2);
                            z = false;
                        } else {
                            com.google.android.gms.ads.internal.util.client.zzb.zzay("Caching " + format + " bytes from " + str);
                            ReadableByteChannel newChannel = Channels.newChannel(openConnection.getInputStream());
                            fileOutputStream = new FileOutputStream(file);
                            try {
                                FileChannel channel = fileOutputStream.getChannel();
                                ByteBuffer allocate = ByteBuffer.allocate(AccessibilityEventCompat.TYPE_TOUCH_INTERACTION_START);
                                zzlb zzbz = com.google.android.gms.ads.internal.zzo.zzbz();
                                long currentTimeMillis = zzbz.currentTimeMillis();
                                zzhq zzhqVar = new zzhq(zzbz.zztR.get().longValue());
                                long longValue = zzbz.zztQ.get().longValue();
                                int i = 0;
                                while (true) {
                                    int read = newChannel.read(allocate);
                                    if (read >= 0) {
                                        i += read;
                                        if (i > intValue2) {
                                            throw new IOException("stream cache file size limit exceeded");
                                        }
                                        allocate.flip();
                                        do {
                                        } while (channel.write(allocate) > 0);
                                        allocate.clear();
                                        if (zzbz.currentTimeMillis() - currentTimeMillis > 1000 * longValue) {
                                            throw new IOException("stream cache time limit exceeded");
                                        }
                                        if (this.zzwI) {
                                            throw new IOException("abort requested");
                                        }
                                        if (zzhqVar.tryAcquire()) {
                                            zza(str, file, i, contentLength);
                                        }
                                    } else {
                                        fileOutputStream.close();
                                        if (com.google.android.gms.ads.internal.util.client.zzb.zzL(3)) {
                                            com.google.android.gms.ads.internal.util.client.zzb.zzay("Preloaded " + zzwG.format(i) + " bytes from " + str);
                                        }
                                        file.setReadable(true, false);
                                        zzb(zza);
                                        zza(str, file, i);
                                        zzwF.remove(str2);
                                        z = true;
                                    }
                                }
                            } catch (IOException e) {
                                e = e;
                                try {
                                    fileOutputStream.close();
                                } catch (IOException e2) {
                                } catch (NullPointerException e3) {
                                }
                                if (this.zzwI) {
                                    com.google.android.gms.ads.internal.util.client.zzb.zzaA("Preload aborted for URL \"" + str + "\"");
                                } else {
                                    com.google.android.gms.ads.internal.util.client.zzb.zzd("Preload failed for URL \"" + str + "\"", e);
                                }
                                if (file.exists() && !file.delete()) {
                                    com.google.android.gms.ads.internal.util.client.zzb.zzaC("Could not delete partial cache file at " + file.getAbsolutePath());
                                }
                                zza(str, file);
                                zzwF.remove(str2);
                                z = false;
                                return z;
                            }
                        }
                    }
                } catch (IOException e4) {
                    e = e4;
                    fileOutputStream = null;
                }
            }
        }
        return z;
    }

    public int zzdQ() {
        int i = 0;
        if (this.zzwH != null) {
            for (File file : this.zzwH.listFiles()) {
                if (!file.getName().endsWith(".done")) {
                    i++;
                }
            }
        }
        return i;
    }

    public boolean zzdR() {
        boolean z;
        long j;
        File file;
        if (this.zzwH == null) {
            return false;
        }
        File file2 = null;
        long j2 = Long.MAX_VALUE;
        File[] listFiles = this.zzwH.listFiles();
        int length = listFiles.length;
        int i = 0;
        while (i < length) {
            File file3 = listFiles[i];
            if (!file3.getName().endsWith(".done")) {
                j = file3.lastModified();
                if (j < j2) {
                    file = file3;
                    i++;
                    file2 = file;
                    j2 = j;
                }
            }
            j = j2;
            file = file2;
            i++;
            file2 = file;
            j2 = j;
        }
        if (file2 != null) {
            z = file2.delete();
            File zza = zza(file2);
            if (zza.isFile()) {
                z &= zza.delete();
            }
        } else {
            z = false;
        }
        return z;
    }
}
