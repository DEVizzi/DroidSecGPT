package com.google.android.gms.internal;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.List;
/* loaded from: classes.dex */
public class zzqi {
    private String zzaLc = "https://www.google-analytics.com";

    private String zzeQ(String str) {
        try {
            return URLEncoder.encode(str, "UTF-8").replaceAll("\\+", "%20");
        } catch (UnsupportedEncodingException e) {
            com.google.android.gms.tagmanager.zzbg.zzaz("Cannot encode the string: " + str);
            return "";
        }
    }

    public void zzeU(String str) {
        this.zzaLc = str;
        com.google.android.gms.tagmanager.zzbg.zzaA("The Ctfe server endpoint was changed to: " + str);
    }

    public String zzt(List<zzpy> list) {
        return this.zzaLc + "/gtm/android?" + zzu(list);
    }

    String zzu(List<zzpy> list) {
        com.google.android.gms.common.internal.zzu.zzV(list.size() <= 1);
        if (list.isEmpty()) {
            return "";
        }
        zzpy zzpyVar = list.get(0);
        String trim = !zzpyVar.zzAd().trim().equals("") ? zzpyVar.zzAd().trim() : "-1";
        StringBuilder sb = new StringBuilder();
        if (zzpyVar.zzAa() != null) {
            sb.append(zzpyVar.zzAa());
        } else {
            sb.append("id");
        }
        sb.append("=").append(zzeQ(zzpyVar.getContainerId())).append("&").append("pv").append("=").append(zzeQ(trim));
        if (zzpyVar.zzAc()) {
            sb.append("&gtm_debug=x");
        }
        return sb.toString();
    }
}
