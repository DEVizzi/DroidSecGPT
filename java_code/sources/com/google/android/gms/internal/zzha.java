package com.google.android.gms.internal;

import com.google.android.gms.ads.internal.client.AdRequestParcel;
import com.google.android.gms.ads.internal.client.AdSizeParcel;
import com.google.android.gms.ads.internal.formats.zzg;
import com.google.android.gms.ads.internal.request.AdRequestInfoParcel;
import com.google.android.gms.ads.internal.request.AdResponseParcel;
import java.util.Collections;
import java.util.List;
import org.json.JSONObject;
@zzgd
/* loaded from: classes.dex */
public class zzha {
    public final int errorCode;
    public final int orientation;
    public final String zzCC;
    public final long zzCJ;
    public final boolean zzCK;
    public final long zzCL;
    public final List<String> zzCM;
    public final String zzCP;
    public final AdRequestParcel zzCm;
    public final String zzCp;
    public final JSONObject zzFl;
    public final zzdy zzFm;
    public final AdSizeParcel zzFn;
    public final long zzFo;
    public final long zzFp;
    public final zzg.zza zzFq;
    public final List<String> zzxF;
    public final List<String> zzxG;
    public final long zzxJ;
    public final zzdx zzxZ;
    public final zzeg zzya;
    public final String zzyb;
    public final zzea zzyc;
    public final zzid zzzE;

    @zzgd
    /* loaded from: classes.dex */
    public static final class zza {
        public final int errorCode;
        public final JSONObject zzFl;
        public final zzdy zzFm;
        public final long zzFo;
        public final long zzFp;
        public final AdRequestInfoParcel zzFr;
        public final AdResponseParcel zzFs;
        public final AdSizeParcel zzpN;

        public zza(AdRequestInfoParcel adRequestInfoParcel, AdResponseParcel adResponseParcel, zzdy zzdyVar, AdSizeParcel adSizeParcel, int i, long j, long j2, JSONObject jSONObject) {
            this.zzFr = adRequestInfoParcel;
            this.zzFs = adResponseParcel;
            this.zzFm = zzdyVar;
            this.zzpN = adSizeParcel;
            this.errorCode = i;
            this.zzFo = j;
            this.zzFp = j2;
            this.zzFl = jSONObject;
        }
    }

    public zzha(AdRequestParcel adRequestParcel, zzid zzidVar, List<String> list, int i, List<String> list2, List<String> list3, int i2, long j, String str, boolean z, zzdx zzdxVar, zzeg zzegVar, String str2, zzdy zzdyVar, zzea zzeaVar, long j2, AdSizeParcel adSizeParcel, long j3, long j4, long j5, String str3, JSONObject jSONObject, zzg.zza zzaVar, String str4) {
        this.zzCm = adRequestParcel;
        this.zzzE = zzidVar;
        this.zzxF = list != null ? Collections.unmodifiableList(list) : null;
        this.errorCode = i;
        this.zzxG = list2 != null ? Collections.unmodifiableList(list2) : null;
        this.zzCM = list3 != null ? Collections.unmodifiableList(list3) : null;
        this.orientation = i2;
        this.zzxJ = j;
        this.zzCp = str;
        this.zzCK = z;
        this.zzxZ = zzdxVar;
        this.zzya = zzegVar;
        this.zzyb = str2;
        this.zzFm = zzdyVar;
        this.zzyc = zzeaVar;
        this.zzCL = j2;
        this.zzFn = adSizeParcel;
        this.zzCJ = j3;
        this.zzFo = j4;
        this.zzFp = j5;
        this.zzCP = str3;
        this.zzFl = jSONObject;
        this.zzFq = zzaVar;
        this.zzCC = str4;
    }

    public zzha(zza zzaVar, zzid zzidVar, zzdx zzdxVar, zzeg zzegVar, String str, zzea zzeaVar, zzg.zza zzaVar2) {
        this(zzaVar.zzFr.zzCm, zzidVar, zzaVar.zzFs.zzxF, zzaVar.errorCode, zzaVar.zzFs.zzxG, zzaVar.zzFs.zzCM, zzaVar.zzFs.orientation, zzaVar.zzFs.zzxJ, zzaVar.zzFr.zzCp, zzaVar.zzFs.zzCK, zzdxVar, zzegVar, str, zzaVar.zzFm, zzeaVar, zzaVar.zzFs.zzCL, zzaVar.zzpN, zzaVar.zzFs.zzCJ, zzaVar.zzFo, zzaVar.zzFp, zzaVar.zzFs.zzCP, zzaVar.zzFl, zzaVar2, zzaVar.zzFr.zzCC);
    }

    public boolean zzbU() {
        if (this.zzzE == null || this.zzzE.zzgF() == null) {
            return false;
        }
        return this.zzzE.zzgF().zzbU();
    }
}
