package com.google.android.gms.internal;

import com.google.android.gms.plus.PlusShare;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
/* JADX INFO: Access modifiers changed from: package-private */
@zzgd
/* loaded from: classes.dex */
public class zzgj {
    private int zzBv;
    private final String zzDK;
    private final List<String> zzEg;
    private final List<String> zzEh;
    private final String zzEi;
    private final String zzEj;
    private final String zzEk;
    private final String zzEl;
    private final boolean zzEm;
    private String zzF;

    public zzgj(int i, Map<String, String> map) {
        this.zzF = map.get(PlusShare.KEY_CALL_TO_ACTION_URL);
        this.zzEj = map.get("base_uri");
        this.zzEk = map.get("post_parameters");
        this.zzEm = parseBoolean(map.get("drt_include"));
        this.zzEi = map.get("activation_overlay_url");
        this.zzEh = zzan(map.get("check_packages"));
        this.zzDK = map.get("request_id");
        this.zzEl = map.get("type");
        this.zzEg = zzan(map.get("errors"));
        this.zzBv = i;
    }

    private static boolean parseBoolean(String bool) {
        return bool != null && (bool.equals("1") || bool.equals("true"));
    }

    private List<String> zzan(String str) {
        if (str == null) {
            return null;
        }
        return Arrays.asList(str.split(","));
    }

    public int getErrorCode() {
        return this.zzBv;
    }

    public String getRequestId() {
        return this.zzDK;
    }

    public String getType() {
        return this.zzEl;
    }

    public String getUrl() {
        return this.zzF;
    }

    public void setUrl(String url) {
        this.zzF = url;
    }

    public List<String> zzfG() {
        return this.zzEg;
    }

    public String zzfH() {
        return this.zzEk;
    }

    public boolean zzfI() {
        return this.zzEm;
    }
}
