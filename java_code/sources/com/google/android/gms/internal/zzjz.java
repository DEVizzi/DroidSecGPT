package com.google.android.gms.internal;

import android.text.TextUtils;
import com.google.android.gms.common.images.WebImage;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
/* loaded from: classes.dex */
public class zzjz {
    private static final com.google.android.gms.cast.internal.zzl zzQW = new com.google.android.gms.cast.internal.zzl("MetadataUtils");
    private static final String[] zzVs = {"Z", "+hh", "+hhmm", "+hh:mm"};
    private static final String zzVt = "yyyyMMdd'T'HHmmss" + zzVs[0];

    public static String zza(Calendar calendar) {
        if (calendar == null) {
            zzQW.zzb("Calendar object cannot be null", new Object[0]);
            return null;
        }
        String str = zzVt;
        if (calendar.get(11) == 0 && calendar.get(12) == 0 && calendar.get(13) == 0) {
            str = "yyyyMMdd";
        }
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(str);
        simpleDateFormat.setTimeZone(calendar.getTimeZone());
        String format = simpleDateFormat.format(calendar.getTime());
        return format.endsWith("+0000") ? format.replace("+0000", zzVs[0]) : format;
    }

    public static void zza(List<WebImage> list, JSONObject jSONObject) {
        try {
            list.clear();
            JSONArray jSONArray = jSONObject.getJSONArray("images");
            int length = jSONArray.length();
            for (int i = 0; i < length; i++) {
                try {
                    list.add(new WebImage(jSONArray.getJSONObject(i)));
                } catch (IllegalArgumentException e) {
                }
            }
        } catch (JSONException e2) {
        }
    }

    public static void zza(JSONObject jSONObject, List<WebImage> list) {
        if (list == null || list.isEmpty()) {
            return;
        }
        JSONArray jSONArray = new JSONArray();
        for (WebImage webImage : list) {
            jSONArray.put(webImage.toJson());
        }
        try {
            jSONObject.put("images", jSONArray);
        } catch (JSONException e) {
        }
    }

    public static Calendar zzbK(String str) {
        if (TextUtils.isEmpty(str)) {
            zzQW.zzb("Input string is empty or null", new Object[0]);
            return null;
        }
        String zzbL = zzbL(str);
        if (TextUtils.isEmpty(zzbL)) {
            zzQW.zzb("Invalid date format", new Object[0]);
            return null;
        }
        String zzbM = zzbM(str);
        String str2 = "yyyyMMdd";
        if (!TextUtils.isEmpty(zzbM)) {
            zzbL = zzbL + "T" + zzbM;
            str2 = zzbM.length() == "HHmmss".length() ? "yyyyMMdd'T'HHmmss" : zzVt;
        }
        Calendar gregorianCalendar = GregorianCalendar.getInstance();
        try {
            gregorianCalendar.setTime(new SimpleDateFormat(str2).parse(zzbL));
            return gregorianCalendar;
        } catch (ParseException e) {
            zzQW.zzb("Error parsing string: %s", e.getMessage());
            return null;
        }
    }

    private static String zzbL(String str) {
        if (TextUtils.isEmpty(str)) {
            zzQW.zzb("Input string is empty or null", new Object[0]);
            return null;
        }
        try {
            return str.substring(0, "yyyyMMdd".length());
        } catch (IndexOutOfBoundsException e) {
            zzQW.zze("Error extracting the date: %s", e.getMessage());
            return null;
        }
    }

    private static String zzbM(String str) {
        if (TextUtils.isEmpty(str)) {
            zzQW.zzb("string is empty or null", new Object[0]);
            return null;
        }
        int indexOf = str.indexOf(84);
        int i = indexOf + 1;
        if (indexOf != "yyyyMMdd".length()) {
            zzQW.zzb("T delimeter is not found", new Object[0]);
            return null;
        }
        try {
            String substring = str.substring(i);
            if (substring.length() == "HHmmss".length()) {
                return substring;
            }
            switch (substring.charAt("HHmmss".length())) {
                case '+':
                case '-':
                    if (zzbN(substring)) {
                        return substring.replaceAll("([\\+\\-]\\d\\d):(\\d\\d)", "$1$2");
                    }
                    return null;
                case 'Z':
                    if (substring.length() == "HHmmss".length() + zzVs[0].length()) {
                        return substring.substring(0, substring.length() - 1) + "+0000";
                    }
                    return null;
                default:
                    return null;
            }
        } catch (IndexOutOfBoundsException e) {
            zzQW.zzb("Error extracting the time substring: %s", e.getMessage());
            return null;
        }
    }

    private static boolean zzbN(String str) {
        int length = str.length();
        int length2 = "HHmmss".length();
        return length == zzVs[1].length() + length2 || length == zzVs[2].length() + length2 || length == length2 + zzVs[3].length();
    }
}
