package com.google.android.gms.internal;

import com.google.android.gms.internal.zzqf;
import org.json.JSONException;
/* loaded from: classes.dex */
public final class zzqc {
    public static zzqb zzaPm = new zzqb() { // from class: com.google.android.gms.internal.zzqc.1
        @Override // com.google.android.gms.internal.zzqb
        public Object zzt(byte[] bArr) throws zzqf.zzg {
            if (bArr == null) {
                throw new zzqf.zzg("Cannot parse a null byte[]");
            }
            if (bArr.length == 0) {
                throw new zzqf.zzg("Cannot parse a 0 length byte[]");
            }
            try {
                zzqf.zzc zzey = zzpz.zzey(new String(bArr));
                if (zzey != null) {
                    com.google.android.gms.tagmanager.zzbg.zzaB("The container was successfully parsed from the resource");
                }
                return zzey;
            } catch (zzqf.zzg e) {
                throw new zzqf.zzg("The resource data is invalid. The container cannot be extracted from the binary data");
            } catch (JSONException e2) {
                throw new zzqf.zzg("The resource data is corrupted. The container cannot be extracted from the binary data");
            }
        }
    };
}
