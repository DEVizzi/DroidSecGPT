package com.google.android.gms.analytics.internal;

import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.GZIPOutputStream;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zzah extends zzd {
    private static final byte[] zzMs = "\n".getBytes();
    private final String zzFP;
    private final zzaj zzMr;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class zza {
        private int zzMt;
        private ByteArrayOutputStream zzMu = new ByteArrayOutputStream();

        public zza() {
        }

        public byte[] getPayload() {
            return this.zzMu.toByteArray();
        }

        public boolean zzj(zzab zzabVar) {
            com.google.android.gms.common.internal.zzu.zzu(zzabVar);
            if (this.zzMt + 1 > zzah.this.zzhR().zzji()) {
                return false;
            }
            String zza = zzah.this.zza(zzabVar, false);
            if (zza == null) {
                zzah.this.zzhQ().zza(zzabVar, "Error formatting hit");
                return true;
            }
            byte[] bytes = zza.getBytes();
            int length = bytes.length;
            if (length > zzah.this.zzhR().zzja()) {
                zzah.this.zzhQ().zza(zzabVar, "Hit size exceeds the maximum size limit");
                return true;
            }
            if (this.zzMu.size() > 0) {
                length++;
            }
            if (length + this.zzMu.size() > zzah.this.zzhR().zzjc()) {
                return false;
            }
            try {
                if (this.zzMu.size() > 0) {
                    this.zzMu.write(zzah.zzMs);
                }
                this.zzMu.write(bytes);
                this.zzMt++;
                return true;
            } catch (IOException e) {
                zzah.this.zze("Failed to write payload when batching hits", e);
                return true;
            }
        }

        public int zzkj() {
            return this.zzMt;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzah(zzf zzfVar) {
        super(zzfVar);
        this.zzFP = zza("GoogleAnalytics", zze.VERSION, Build.VERSION.RELEASE, zzam.zza(Locale.getDefault()), Build.MODEL, Build.ID);
        this.zzMr = new zzaj(zzfVar.zzhP());
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0087  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0082 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r2v10 */
    /* JADX WARN: Type inference failed for: r2v2 */
    /* JADX WARN: Type inference failed for: r2v3 */
    /* JADX WARN: Type inference failed for: r2v5, types: [java.net.HttpURLConnection] */
    /* JADX WARN: Type inference failed for: r2v9 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private int zza(java.net.URL r6, byte[] r7) {
        /*
            r5 = this;
            r1 = 0
            com.google.android.gms.common.internal.zzu.zzu(r6)
            com.google.android.gms.common.internal.zzu.zzu(r7)
            java.lang.String r0 = "POST bytes, url"
            int r2 = r7.length
            java.lang.Integer r2 = java.lang.Integer.valueOf(r2)
            r5.zzb(r0, r2, r6)
            boolean r0 = r5.zzhZ()
            if (r0 == 0) goto L21
            java.lang.String r0 = "Post payload\n"
            java.lang.String r2 = new java.lang.String
            r2.<init>(r7)
            r5.zza(r0, r2)
        L21:
            java.net.HttpURLConnection r2 = r5.zzc(r6)     // Catch: java.io.IOException -> L64 java.lang.Throwable -> L7e
            r0 = 1
            r2.setDoOutput(r0)     // Catch: java.lang.Throwable -> L92 java.io.IOException -> L94
            int r0 = r7.length     // Catch: java.lang.Throwable -> L92 java.io.IOException -> L94
            r2.setFixedLengthStreamingMode(r0)     // Catch: java.lang.Throwable -> L92 java.io.IOException -> L94
            r2.connect()     // Catch: java.lang.Throwable -> L92 java.io.IOException -> L94
            java.io.OutputStream r1 = r2.getOutputStream()     // Catch: java.lang.Throwable -> L92 java.io.IOException -> L94
            r1.write(r7)     // Catch: java.lang.Throwable -> L92 java.io.IOException -> L94
            r5.zzb(r2)     // Catch: java.lang.Throwable -> L92 java.io.IOException -> L94
            int r0 = r2.getResponseCode()     // Catch: java.lang.Throwable -> L92 java.io.IOException -> L94
            r3 = 200(0xc8, float:2.8E-43)
            if (r0 != r3) goto L49
            com.google.android.gms.analytics.internal.zzb r3 = r5.zzhl()     // Catch: java.lang.Throwable -> L92 java.io.IOException -> L94
            r3.zzhL()     // Catch: java.lang.Throwable -> L92 java.io.IOException -> L94
        L49:
            java.lang.String r3 = "POST status"
            java.lang.Integer r4 = java.lang.Integer.valueOf(r0)     // Catch: java.lang.Throwable -> L92 java.io.IOException -> L94
            r5.zzb(r3, r4)     // Catch: java.lang.Throwable -> L92 java.io.IOException -> L94
            if (r1 == 0) goto L57
            r1.close()     // Catch: java.io.IOException -> L5d
        L57:
            if (r2 == 0) goto L5c
            r2.disconnect()
        L5c:
            return r0
        L5d:
            r1 = move-exception
            java.lang.String r3 = "Error closing http post connection output stream"
            r5.zze(r3, r1)
            goto L57
        L64:
            r0 = move-exception
            r2 = r1
        L66:
            java.lang.String r3 = "Network POST connection error"
            r5.zzd(r3, r0)     // Catch: java.lang.Throwable -> L92
            r0 = 0
            if (r1 == 0) goto L71
            r1.close()     // Catch: java.io.IOException -> L77
        L71:
            if (r2 == 0) goto L5c
            r2.disconnect()
            goto L5c
        L77:
            r1 = move-exception
            java.lang.String r3 = "Error closing http post connection output stream"
            r5.zze(r3, r1)
            goto L71
        L7e:
            r0 = move-exception
            r2 = r1
        L80:
            if (r1 == 0) goto L85
            r1.close()     // Catch: java.io.IOException -> L8b
        L85:
            if (r2 == 0) goto L8a
            r2.disconnect()
        L8a:
            throw r0
        L8b:
            r1 = move-exception
            java.lang.String r3 = "Error closing http post connection output stream"
            r5.zze(r3, r1)
            goto L85
        L92:
            r0 = move-exception
            goto L80
        L94:
            r0 = move-exception
            goto L66
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.analytics.internal.zzah.zza(java.net.URL, byte[]):int");
    }

    private static String zza(String str, String str2, String str3, String str4, String str5, String str6) {
        return String.format("%s/%s (Linux; U; Android %s; %s; %s Build/%s)", str, str2, str3, str4, str5, str6);
    }

    private void zza(StringBuilder sb, String str, String str2) throws UnsupportedEncodingException {
        if (sb.length() != 0) {
            sb.append('&');
        }
        sb.append(URLEncoder.encode(str, "UTF-8"));
        sb.append('=');
        sb.append(URLEncoder.encode(str2, "UTF-8"));
    }

    private int zzb(URL url) {
        int i;
        com.google.android.gms.common.internal.zzu.zzu(url);
        zzb("GET request", url);
        HttpURLConnection httpURLConnection = null;
        try {
            try {
                httpURLConnection = zzc(url);
                httpURLConnection.connect();
                zzb(httpURLConnection);
                i = httpURLConnection.getResponseCode();
                if (i == 200) {
                    zzhl().zzhL();
                }
                zzb("GET status", Integer.valueOf(i));
            } catch (IOException e) {
                zzd("Network GET connection error", e);
                i = 0;
                if (httpURLConnection != null) {
                    httpURLConnection.disconnect();
                }
            }
            return i;
        } finally {
            if (httpURLConnection != null) {
                httpURLConnection.disconnect();
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:40:0x00c8  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00c3 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private int zzb(java.net.URL r9, byte[] r10) {
        /*
            Method dump skipped, instructions count: 226
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.analytics.internal.zzah.zzb(java.net.URL, byte[]):int");
    }

    private URL zzb(zzab zzabVar, String str) {
        try {
            return new URL(zzabVar.zzjY() ? zzhR().zzjk() + zzhR().zzjm() + "?" + str : zzhR().zzjl() + zzhR().zzjm() + "?" + str);
        } catch (MalformedURLException e) {
            zze("Error trying to parse the hardcoded host url", e);
            return null;
        }
    }

    private void zzb(HttpURLConnection httpURLConnection) throws IOException {
        InputStream inputStream = null;
        try {
            inputStream = httpURLConnection.getInputStream();
            do {
            } while (inputStream.read(new byte[1024]) > 0);
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    zze("Error closing http connection input stream", e);
                }
            }
        } catch (Throwable th) {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e2) {
                    zze("Error closing http connection input stream", e2);
                }
            }
            throw th;
        }
    }

    private boolean zzg(zzab zzabVar) {
        com.google.android.gms.common.internal.zzu.zzu(zzabVar);
        String zza2 = zza(zzabVar, !zzabVar.zzjY());
        if (zza2 == null) {
            zzhQ().zza(zzabVar, "Error formatting hit for upload");
            return true;
        } else if (zza2.length() <= zzhR().zziZ()) {
            URL zzb = zzb(zzabVar, zza2);
            if (zzb != null) {
                return zzb(zzb) == 200;
            }
            zzaX("Failed to build collect GET endpoint url");
            return false;
        } else {
            String zza3 = zza(zzabVar, false);
            if (zza3 == null) {
                zzhQ().zza(zzabVar, "Error formatting hit for POST upload");
                return true;
            }
            byte[] bytes = zza3.getBytes();
            if (bytes.length > zzhR().zzjb()) {
                zzhQ().zza(zzabVar, "Hit payload exceeds size limit");
                return true;
            }
            URL zzh = zzh(zzabVar);
            if (zzh != null) {
                return zza(zzh, bytes) == 200;
            }
            zzaX("Failed to build collect POST endpoint url");
            return false;
        }
    }

    private static byte[] zzg(byte[] bArr) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        GZIPOutputStream gZIPOutputStream = new GZIPOutputStream(byteArrayOutputStream);
        gZIPOutputStream.write(bArr);
        gZIPOutputStream.close();
        byteArrayOutputStream.close();
        return byteArrayOutputStream.toByteArray();
    }

    private URL zzh(zzab zzabVar) {
        try {
            return new URL(zzabVar.zzjY() ? zzhR().zzjk() + zzhR().zzjm() : zzhR().zzjl() + zzhR().zzjm());
        } catch (MalformedURLException e) {
            zze("Error trying to parse the hardcoded host url", e);
            return null;
        }
    }

    private String zzi(zzab zzabVar) {
        return String.valueOf(zzabVar.zzjV());
    }

    private URL zzkh() {
        try {
            return new URL(zzhR().zzjk() + zzhR().zzjn());
        } catch (MalformedURLException e) {
            zze("Error trying to parse the hardcoded host url", e);
            return null;
        }
    }

    String zza(zzab zzabVar, boolean z) {
        com.google.android.gms.common.internal.zzu.zzu(zzabVar);
        StringBuilder sb = new StringBuilder();
        try {
            for (Map.Entry<String, String> entry : zzabVar.zzn().entrySet()) {
                String key = entry.getKey();
                if (!"ht".equals(key) && !"qt".equals(key) && !"AppUID".equals(key) && !"z".equals(key) && !"_gmsv".equals(key)) {
                    zza(sb, key, entry.getValue());
                }
            }
            zza(sb, "ht", String.valueOf(zzabVar.zzjW()));
            zza(sb, "qt", String.valueOf(zzhP().currentTimeMillis() - zzabVar.zzjW()));
            if (zzhR().zziW()) {
                zza(sb, "_gmsv", zze.VERSION);
            }
            if (z) {
                long zzjZ = zzabVar.zzjZ();
                zza(sb, "z", zzjZ != 0 ? String.valueOf(zzjZ) : zzi(zzabVar));
            }
            return sb.toString();
        } catch (UnsupportedEncodingException e) {
            zze("Failed to encode name or value", e);
            return null;
        }
    }

    List<Long> zza(List<zzab> list, boolean z) {
        com.google.android.gms.common.internal.zzu.zzV(!list.isEmpty());
        zza("Uploading batched hits. compression, count", Boolean.valueOf(z), Integer.valueOf(list.size()));
        zza zzaVar = new zza();
        ArrayList arrayList = new ArrayList();
        for (zzab zzabVar : list) {
            if (!zzaVar.zzj(zzabVar)) {
                break;
            }
            arrayList.add(Long.valueOf(zzabVar.zzjV()));
        }
        if (zzaVar.zzkj() == 0) {
            return arrayList;
        }
        URL zzkh = zzkh();
        if (zzkh == null) {
            zzaX("Failed to build batching endpoint url");
            return Collections.emptyList();
        }
        int zzb = z ? zzb(zzkh, zzaVar.getPayload()) : zza(zzkh, zzaVar.getPayload());
        if (200 == zzb) {
            zza("Batched upload completed. Hits batched", Integer.valueOf(zzaVar.zzkj()));
            return arrayList;
        }
        zza("Network error uploading hits. status code", Integer.valueOf(zzb));
        if (zzhR().zzjq().contains(Integer.valueOf(zzb))) {
            zzaW("Server instructed the client to stop batching");
            this.zzMr.start();
        }
        return Collections.emptyList();
    }

    HttpURLConnection zzc(URL url) throws IOException {
        URLConnection openConnection = url.openConnection();
        if (openConnection instanceof HttpURLConnection) {
            HttpURLConnection httpURLConnection = (HttpURLConnection) openConnection;
            httpURLConnection.setDefaultUseCaches(false);
            httpURLConnection.setConnectTimeout(zzhR().zzjz());
            httpURLConnection.setReadTimeout(zzhR().zzjA());
            httpURLConnection.setInstanceFollowRedirects(false);
            httpURLConnection.setRequestProperty("User-Agent", this.zzFP);
            httpURLConnection.setDoInput(true);
            return httpURLConnection;
        }
        throw new IOException("Failed to obtain http connection");
    }

    public List<Long> zzf(List<zzab> list) {
        boolean z;
        boolean z2 = true;
        zzhO();
        zzia();
        com.google.android.gms.common.internal.zzu.zzu(list);
        if (zzhR().zzjq().isEmpty() || !this.zzMr.zzv(zzhR().zzjj() * 1000)) {
            z2 = false;
            z = false;
        } else {
            z = zzhR().zzjo() != zzm.NONE;
            if (zzhR().zzjp() != zzo.GZIP) {
                z2 = false;
            }
        }
        return z ? zza(list, z2) : zzg(list);
    }

    List<Long> zzg(List<zzab> list) {
        ArrayList arrayList = new ArrayList(list.size());
        for (zzab zzabVar : list) {
            if (!zzg(zzabVar)) {
                break;
            }
            arrayList.add(Long.valueOf(zzabVar.zzjV()));
            if (arrayList.size() >= zzhR().zzjh()) {
                break;
            }
        }
        return arrayList;
    }

    @Override // com.google.android.gms.analytics.internal.zzd
    protected void zzhn() {
        zza("Network initialized. User agent", this.zzFP);
    }

    public boolean zzkg() {
        NetworkInfo networkInfo;
        zzhO();
        zzia();
        try {
            networkInfo = ((ConnectivityManager) getContext().getSystemService("connectivity")).getActiveNetworkInfo();
        } catch (SecurityException e) {
            networkInfo = null;
        }
        if (networkInfo == null || !networkInfo.isConnected()) {
            zzaT("No network connectivity");
            return false;
        }
        return true;
    }
}
