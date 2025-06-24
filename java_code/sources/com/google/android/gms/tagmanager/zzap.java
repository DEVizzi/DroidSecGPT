package com.google.android.gms.tagmanager;

import com.google.android.gms.internal.zzag;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zzap extends zzak {
    private static final String ID = com.google.android.gms.internal.zzad.HASH.toString();
    private static final String zzaLE = com.google.android.gms.internal.zzae.ARG0.toString();
    private static final String zzaLK = com.google.android.gms.internal.zzae.ALGORITHM.toString();
    private static final String zzaLG = com.google.android.gms.internal.zzae.INPUT_FORMAT.toString();

    public zzap() {
        super(ID, zzaLE);
    }

    private byte[] zzd(String str, byte[] bArr) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(str);
        messageDigest.update(bArr);
        return messageDigest.digest();
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public zzag.zza zzE(Map<String, zzag.zza> map) {
        byte[] zzee;
        zzag.zza zzaVar = map.get(zzaLE);
        if (zzaVar == null || zzaVar == zzdf.zzzQ()) {
            return zzdf.zzzQ();
        }
        String zzg = zzdf.zzg(zzaVar);
        zzag.zza zzaVar2 = map.get(zzaLK);
        String zzg2 = zzaVar2 == null ? "MD5" : zzdf.zzg(zzaVar2);
        zzag.zza zzaVar3 = map.get(zzaLG);
        String zzg3 = zzaVar3 == null ? "text" : zzdf.zzg(zzaVar3);
        if ("text".equals(zzg3)) {
            zzee = zzg.getBytes();
        } else if (!"base16".equals(zzg3)) {
            zzbg.zzaz("Hash: unknown input format: " + zzg3);
            return zzdf.zzzQ();
        } else {
            zzee = zzk.zzee(zzg);
        }
        try {
            return zzdf.zzI(zzk.zzi(zzd(zzg2, zzee)));
        } catch (NoSuchAlgorithmException e) {
            zzbg.zzaz("Hash: unknown algorithm: " + zzg2);
            return zzdf.zzzQ();
        }
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public boolean zzyh() {
        return true;
    }
}
