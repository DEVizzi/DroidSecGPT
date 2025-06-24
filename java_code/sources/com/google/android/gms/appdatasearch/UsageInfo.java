package com.google.android.gms.appdatasearch;

import android.content.ComponentName;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Parcel;
import com.google.android.gms.appdatasearch.DocumentContents;
import com.google.android.gms.appdatasearch.RegisterSectionInfo;
import com.google.android.gms.appindexing.AppIndexApi;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.internal.zznj;
import com.google.android.gms.internal.zzrn;
import com.google.android.gms.plus.PlusShare;
import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.zip.CRC32;
/* loaded from: classes.dex */
public class UsageInfo implements SafeParcelable {
    public static final zzj CREATOR = new zzj();
    final int zzCY;
    final DocumentId zzNH;
    final long zzNI;
    int zzNJ;
    final DocumentContents zzNK;
    final boolean zzNL;
    int zzNM;
    int zzNN;
    public final String zztt;

    /* loaded from: classes.dex */
    public static final class zza {
        private String zzHZ;
        private DocumentId zzNH;
        private DocumentContents zzNK;
        private long zzNI = -1;
        private int zzNJ = -1;
        private int zzNM = -1;
        private boolean zzNL = false;
        private int zzNN = 0;

        public zza zzL(boolean z) {
            this.zzNL = z;
            return this;
        }

        public zza zza(DocumentContents documentContents) {
            this.zzNK = documentContents;
            return this;
        }

        public zza zza(DocumentId documentId) {
            this.zzNH = documentId;
            return this;
        }

        public zza zzal(int i) {
            this.zzNJ = i;
            return this;
        }

        public zza zzam(int i) {
            this.zzNN = i;
            return this;
        }

        public UsageInfo zzkN() {
            return new UsageInfo(this.zzNH, this.zzNI, this.zzNJ, this.zzHZ, this.zzNK, this.zzNL, this.zzNM, this.zzNN);
        }

        public zza zzw(long j) {
            this.zzNI = j;
            return this;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public UsageInfo(int versionCode, DocumentId documentId, long timestamp, int usageType, String query, DocumentContents document, boolean isDeviceOnly, int taskPosition, int eventStatus) {
        this.zzCY = versionCode;
        this.zzNH = documentId;
        this.zzNI = timestamp;
        this.zzNJ = usageType;
        this.zztt = query;
        this.zzNK = document;
        this.zzNL = isDeviceOnly;
        this.zzNM = taskPosition;
        this.zzNN = eventStatus;
    }

    private UsageInfo(DocumentId documentId, long timestampMs, int usageType, String query, DocumentContents document, boolean isDeviceOnly, int taskPosition, int eventStatus) {
        this(1, documentId, timestampMs, usageType, query, document, isDeviceOnly, taskPosition, eventStatus);
    }

    public UsageInfo(String packageName, Intent viewIntent, String title, Uri webUrl, String schemaOrgType, List<AppIndexApi.AppIndexingLink> outLinks, int eventStatus) {
        this(1, zza(packageName, viewIntent), System.currentTimeMillis(), 0, (String) null, zza(viewIntent, title, webUrl, schemaOrgType, outLinks).zzkJ(), false, -1, eventStatus);
    }

    public static DocumentContents.zza zza(Intent intent, String str, Uri uri, String str2, List<AppIndexApi.AppIndexingLink> list) {
        String string;
        DocumentContents.zza zzaVar = new DocumentContents.zza();
        zzaVar.zza(zzbt(str));
        if (uri != null) {
            zzaVar.zza(zzh(uri));
        }
        if (list != null) {
            zzaVar.zza(zzh(list));
        }
        String action = intent.getAction();
        if (action != null) {
            zzaVar.zza(zzp("intent_action", action));
        }
        String dataString = intent.getDataString();
        if (dataString != null) {
            zzaVar.zza(zzp("intent_data", dataString));
        }
        ComponentName component = intent.getComponent();
        if (component != null) {
            zzaVar.zza(zzp("intent_activity", component.getClassName()));
        }
        Bundle extras = intent.getExtras();
        if (extras != null && (string = extras.getString("intent_extra_data_key")) != null) {
            zzaVar.zza(zzp("intent_extra_data", string));
        }
        return zzaVar.zzbp(str2).zzI(true);
    }

    public static DocumentId zza(String str, Intent intent) {
        return zzo(str, zzg(intent));
    }

    private static DocumentSection zzbt(String str) {
        return new DocumentSection(str, new RegisterSectionInfo.zza(PlusShare.KEY_CONTENT_DEEP_LINK_METADATA_TITLE).zzaj(1).zzK(true).zzbs("name").zzkM(), "text1");
    }

    private static String zzg(Intent intent) {
        String uri = intent.toUri(1);
        CRC32 crc32 = new CRC32();
        try {
            crc32.update(uri.getBytes("UTF-8"));
            return Long.toHexString(crc32.getValue());
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static DocumentSection zzh(Uri uri) {
        return new DocumentSection(uri.toString(), new RegisterSectionInfo.zza("web_url").zzaj(4).zzJ(true).zzbs(PlusShare.KEY_CALL_TO_ACTION_URL).zzkM());
    }

    private static DocumentSection zzh(List<AppIndexApi.AppIndexingLink> list) {
        zznj.zza zzaVar = new zznj.zza();
        zznj.zza.C0140zza[] c0140zzaArr = new zznj.zza.C0140zza[list.size()];
        int i = 0;
        while (true) {
            int i2 = i;
            if (i2 >= c0140zzaArr.length) {
                zzaVar.zzawk = c0140zzaArr;
                return new DocumentSection(zzrn.zzf(zzaVar), new RegisterSectionInfo.zza("outlinks").zzJ(true).zzbs(".private:outLinks").zzbr("blob").zzkM());
            }
            c0140zzaArr[i2] = new zznj.zza.C0140zza();
            AppIndexApi.AppIndexingLink appIndexingLink = list.get(i2);
            c0140zzaArr[i2].zzawm = appIndexingLink.appIndexingUrl.toString();
            c0140zzaArr[i2].viewId = appIndexingLink.viewId;
            if (appIndexingLink.webUrl != null) {
                c0140zzaArr[i2].zzawn = appIndexingLink.webUrl.toString();
            }
            i = i2 + 1;
        }
    }

    private static DocumentId zzo(String str, String str2) {
        return new DocumentId(str, "", str2);
    }

    private static DocumentSection zzp(String str, String str2) {
        return new DocumentSection(str2, new RegisterSectionInfo.zza(str).zzJ(true).zzkM(), str);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zzj zzjVar = CREATOR;
        return 0;
    }

    public String toString() {
        return String.format("UsageInfo[documentId=%s, timestamp=%d, usageType=%d, status=%d]", this.zzNH, Long.valueOf(this.zzNI), Integer.valueOf(this.zzNJ), Integer.valueOf(this.zzNN));
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzj zzjVar = CREATOR;
        zzj.zza(this, dest, flags);
    }
}
