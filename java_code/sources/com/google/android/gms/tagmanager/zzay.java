package com.google.android.gms.tagmanager;

import com.google.android.gms.internal.zzag;
import com.google.android.gms.plus.PlusShare;
import java.io.UnsupportedEncodingException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zzay extends zzak {
    private static final String ID = com.google.android.gms.internal.zzad.JOINER.toString();
    private static final String zzaLE = com.google.android.gms.internal.zzae.ARG0.toString();
    private static final String zzaLW = com.google.android.gms.internal.zzae.ITEM_SEPARATOR.toString();
    private static final String zzaLX = com.google.android.gms.internal.zzae.KEY_VALUE_SEPARATOR.toString();
    private static final String zzaLY = com.google.android.gms.internal.zzae.ESCAPE.toString();

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public enum zza {
        NONE,
        URL,
        BACKSLASH
    }

    public zzay() {
        super(ID, zzaLE);
    }

    private String zza(String str, zza zzaVar, Set<Character> set) {
        switch (zzaVar) {
            case URL:
                try {
                    return zzdj.zzeQ(str);
                } catch (UnsupportedEncodingException e) {
                    zzbg.zzb("Joiner: unsupported encoding", e);
                    return str;
                }
            case BACKSLASH:
                String replace = str.replace("\\", "\\\\");
                Iterator<Character> it = set.iterator();
                while (true) {
                    String str2 = replace;
                    if (!it.hasNext()) {
                        return str2;
                    }
                    String ch = it.next().toString();
                    replace = str2.replace(ch, "\\" + ch);
                }
            default:
                return str;
        }
    }

    private void zza(StringBuilder sb, String str, zza zzaVar, Set<Character> set) {
        sb.append(zza(str, zzaVar, set));
    }

    private void zza(Set<Character> set, String str) {
        for (int i = 0; i < str.length(); i++) {
            set.add(Character.valueOf(str.charAt(i)));
        }
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public zzag.zza zzE(Map<String, zzag.zza> map) {
        HashSet hashSet;
        zza zzaVar;
        zzag.zza zzaVar2 = map.get(zzaLE);
        if (zzaVar2 == null) {
            return zzdf.zzzQ();
        }
        zzag.zza zzaVar3 = map.get(zzaLW);
        String zzg = zzaVar3 != null ? zzdf.zzg(zzaVar3) : "";
        zzag.zza zzaVar4 = map.get(zzaLX);
        String zzg2 = zzaVar4 != null ? zzdf.zzg(zzaVar4) : "=";
        zza zzaVar5 = zza.NONE;
        zzag.zza zzaVar6 = map.get(zzaLY);
        if (zzaVar6 != null) {
            String zzg3 = zzdf.zzg(zzaVar6);
            if (PlusShare.KEY_CALL_TO_ACTION_URL.equals(zzg3)) {
                zzaVar = zza.URL;
                hashSet = null;
            } else if (!"backslash".equals(zzg3)) {
                zzbg.zzaz("Joiner: unsupported escape type: " + zzg3);
                return zzdf.zzzQ();
            } else {
                zzaVar = zza.BACKSLASH;
                hashSet = new HashSet();
                zza(hashSet, zzg);
                zza(hashSet, zzg2);
                hashSet.remove('\\');
            }
        } else {
            hashSet = null;
            zzaVar = zzaVar5;
        }
        StringBuilder sb = new StringBuilder();
        switch (zzaVar2.type) {
            case 2:
                boolean z = true;
                zzag.zza[] zzaVarArr = zzaVar2.zziS;
                int length = zzaVarArr.length;
                int i = 0;
                while (i < length) {
                    zzag.zza zzaVar7 = zzaVarArr[i];
                    if (!z) {
                        sb.append(zzg);
                    }
                    zza(sb, zzdf.zzg(zzaVar7), zzaVar, hashSet);
                    i++;
                    z = false;
                }
                break;
            case 3:
                for (int i2 = 0; i2 < zzaVar2.zziT.length; i2++) {
                    if (i2 > 0) {
                        sb.append(zzg);
                    }
                    String zzg4 = zzdf.zzg(zzaVar2.zziT[i2]);
                    String zzg5 = zzdf.zzg(zzaVar2.zziU[i2]);
                    zza(sb, zzg4, zzaVar, hashSet);
                    sb.append(zzg2);
                    zza(sb, zzg5, zzaVar, hashSet);
                }
                break;
            default:
                zza(sb, zzdf.zzg(zzaVar2), zzaVar, hashSet);
                break;
        }
        return zzdf.zzI(sb.toString());
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public boolean zzyh() {
        return true;
    }
}
