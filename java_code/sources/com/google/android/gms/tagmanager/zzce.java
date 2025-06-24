package com.google.android.gms.tagmanager;

import com.google.android.gms.internal.zzag;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
/* loaded from: classes.dex */
class zzce extends zzak {
    private static final String ID = com.google.android.gms.internal.zzad.REGEX_GROUP.toString();
    private static final String zzaMO = com.google.android.gms.internal.zzae.ARG0.toString();
    private static final String zzaMP = com.google.android.gms.internal.zzae.ARG1.toString();
    private static final String zzaMQ = com.google.android.gms.internal.zzae.IGNORE_CASE.toString();
    private static final String zzaMR = com.google.android.gms.internal.zzae.GROUP.toString();

    public zzce() {
        super(ID, zzaMO, zzaMP);
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public zzag.zza zzE(Map<String, zzag.zza> map) {
        int i;
        zzag.zza zzaVar = map.get(zzaMO);
        zzag.zza zzaVar2 = map.get(zzaMP);
        if (zzaVar == null || zzaVar == zzdf.zzzQ() || zzaVar2 == null || zzaVar2 == zzdf.zzzQ()) {
            return zzdf.zzzQ();
        }
        int i2 = zzdf.zzk(map.get(zzaMQ)).booleanValue() ? 66 : 64;
        zzag.zza zzaVar3 = map.get(zzaMR);
        if (zzaVar3 != null) {
            Long zzi = zzdf.zzi(zzaVar3);
            if (zzi == zzdf.zzzL()) {
                return zzdf.zzzQ();
            }
            i = zzi.intValue();
            if (i < 0) {
                return zzdf.zzzQ();
            }
        } else {
            i = 1;
        }
        try {
            String zzg = zzdf.zzg(zzaVar);
            String str = null;
            Matcher matcher = Pattern.compile(zzdf.zzg(zzaVar2), i2).matcher(zzg);
            if (matcher.find() && matcher.groupCount() >= i) {
                str = matcher.group(i);
            }
            return str == null ? zzdf.zzzQ() : zzdf.zzI(str);
        } catch (PatternSyntaxException e) {
            return zzdf.zzzQ();
        }
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public boolean zzyh() {
        return true;
    }
}
