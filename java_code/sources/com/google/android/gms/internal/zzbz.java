package com.google.android.gms.internal;

import android.content.Context;
import com.google.android.gms.search.SearchAuth;
import java.util.List;
@zzgd
/* loaded from: classes.dex */
public final class zzbz {
    public static final zzbv<String> zztC = zzbv.zzO("gads:sdk_core_experiment_id");
    public static final zzbv<String> zztD = zzbv.zzc("gads:sdk_core_location", "https://googleads.g.doubleclick.net/mads/static/mad/sdk/native/sdk-core-v40.html");
    public static final zzbv<Boolean> zztE = zzbv.zza("gads:request_builder:singleton_webview", (Boolean) false);
    public static final zzbv<String> zztF = zzbv.zzO("gads:request_builder:singleton_webview_experiment_id");
    public static final zzbv<Boolean> zztG = zzbv.zza("gads:sdk_crash_report_enabled", (Boolean) false);
    public static final zzbv<Boolean> zztH = zzbv.zza("gads:sdk_crash_report_full_stacktrace", (Boolean) false);
    public static final zzbv<Boolean> zztI = zzbv.zza("gads:block_autoclicks", (Boolean) false);
    public static final zzbv<String> zztJ = zzbv.zzO("gads:block_autoclicks_experiment_id");
    public static final zzbv<String> zztK = zzbv.zzP("gads:prefetch:experiment_id");
    public static final zzbv<String> zztL = zzbv.zzO("gads:spam_app_context:experiment_id");
    public static final zzbv<Boolean> zztM = zzbv.zza("gads:spam_app_context:enabled", (Boolean) false);
    public static final zzbv<String> zztN = zzbv.zzO("gads:video_stream_cache:experiment_id");
    public static final zzbv<Integer> zztO = zzbv.zza("gads:video_stream_cache:limit_count", 5);
    public static final zzbv<Integer> zztP = zzbv.zza("gads:video_stream_cache:limit_space", 8388608);
    public static final zzbv<Long> zztQ = zzbv.zzb("gads:video_stream_cache:limit_time_sec", 300);
    public static final zzbv<Long> zztR = zzbv.zzb("gads:video_stream_cache:notify_interval_millis", 1000);
    public static final zzbv<Integer> zztS = zzbv.zza("gads:video_stream_cache:connect_timeout_millis", (int) SearchAuth.StatusCodes.AUTH_DISABLED);
    public static final zzbv<String> zztT = zzbv.zzP("gads:spam_ad_id_decorator:experiment_id");
    public static final zzbv<Boolean> zztU = zzbv.zza("gads:spam_ad_id_decorator:enabled", (Boolean) false);
    public static final zzbv<String> zztV = zzbv.zzc("gad:mraid:url_banner", "https://googleads.g.doubleclick.net/mads/static/mad/sdk/native/mraid/v2/mraid_app_banner.js");
    public static final zzbv<String> zztW = zzbv.zzc("gad:mraid:url_expanded_banner", "https://googleads.g.doubleclick.net/mads/static/mad/sdk/native/mraid/v2/mraid_app_expanded_banner.js");
    public static final zzbv<String> zztX = zzbv.zzc("gad:mraid:url_interstitial", "https://googleads.g.doubleclick.net/mads/static/mad/sdk/native/mraid/v2/mraid_app_interstitial.js");
    public static final zzbv<Boolean> zztY = zzbv.zza("gads:enabled_sdk_csi", (Boolean) false);
    public static final zzbv<Integer> zztZ = zzbv.zza("gads:sdk_csi_batch_size", 20);
    public static final zzbv<String> zzua = zzbv.zzc("gads:sdk_csi_server", "https://csi.gstatic.com/csi");
    public static final zzbv<Boolean> zzub = zzbv.zza("gads:sdk_csi_write_to_file", (Boolean) false);
    public static final zzbv<Boolean> zzuc = zzbv.zza("gads:enable_content_fetching", (Boolean) true);
    public static final zzbv<Integer> zzud = zzbv.zza("gads:content_length_weight", 1);
    public static final zzbv<Integer> zzue = zzbv.zza("gads:content_age_weight", 1);
    public static final zzbv<Integer> zzuf = zzbv.zza("gads:min_content_len", 11);
    public static final zzbv<Integer> zzug = zzbv.zza("gads:fingerprint_number", 10);
    public static final zzbv<Integer> zzuh = zzbv.zza("gads:sleep_sec", 10);
    public static final zzbv<String> zzui = zzbv.zzO("gads:kitkat_interstitial_workaround:experiment_id");
    public static final zzbv<Boolean> zzuj = zzbv.zza("gads:kitkat_interstitial_workaround:enabled", (Boolean) true);
    public static final zzbv<Boolean> zzuk = zzbv.zza("gads:interstitial_follow_url", (Boolean) true);
    public static final zzbv<Boolean> zzul = zzbv.zza("gads:interstitial_follow_url:register_click", (Boolean) true);
    public static final zzbv<String> zzum = zzbv.zzO("gads:interstitial_follow_url:experiment_id");
    public static final zzbv<Boolean> zzun = zzbv.zza("gads:analytics_enabled", (Boolean) true);
    public static final zzbv<Boolean> zzuo = zzbv.zza("gads:ad_key_enabled", (Boolean) false);
    public static final zzbv<Integer> zzup = zzbv.zza("gads:webview_cache_version", 0);
    public static final zzbv<String> zzuq = zzbv.zzP("gads:pan:experiment_id");
    public static final zzbv<String> zzur = zzbv.zzc("gads:native:engine_url", "//googleads.g.doubleclick.net/mads/static/mad/sdk/native/native_ads.html");
    public static final zzbv<Boolean> zzus = zzbv.zza("gads:ad_manager_creator:enabled", (Boolean) true);
    public static final zzbv<Boolean> zzut = zzbv.zza("gads:log:verbose_enabled", (Boolean) false);
    public static final zzbv<Boolean> zzuu = zzbv.zza("gads:sdk_less_mediation:enabled", (Boolean) true);
    public static final zzbv<Boolean> zzuv = zzbv.zza("gads:device_info_caching:enabled", (Boolean) true);
    public static final zzbv<Long> zzuw = zzbv.zzb("gads:device_info_caching_expiry_ms:expiry", 300000);
    public static final zzbv<Boolean> zzux = zzbv.zza("gads:gen204_signals:enabled", (Boolean) false);

    public static List<String> zzdb() {
        return com.google.android.gms.ads.internal.zzo.zzbD().zzdb();
    }

    public static void zzw(Context context) {
        com.google.android.gms.ads.internal.zzo.zzbE().zzw(context);
    }

    public static List<String> zzx(Context context) {
        if (com.google.android.gms.ads.internal.client.zzk.zzcA().zzP(context)) {
            return com.google.android.gms.ads.internal.zzo.zzbD().zzda();
        }
        return null;
    }
}
