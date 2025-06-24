package com.google.android.gms.cast;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.accessibility.CaptioningManager;
import com.google.android.gms.cast.internal.zzf;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.internal.zzlh;
import com.google.android.gms.internal.zzlk;
import org.json.JSONException;
import org.json.JSONObject;
/* loaded from: classes.dex */
public final class TextTrackStyle {
    public static final int COLOR_UNSPECIFIED = 0;
    public static final float DEFAULT_FONT_SCALE = 1.0f;
    public static final int EDGE_TYPE_DEPRESSED = 4;
    public static final int EDGE_TYPE_DROP_SHADOW = 2;
    public static final int EDGE_TYPE_NONE = 0;
    public static final int EDGE_TYPE_OUTLINE = 1;
    public static final int EDGE_TYPE_RAISED = 3;
    public static final int EDGE_TYPE_UNSPECIFIED = -1;
    public static final int FONT_FAMILY_CASUAL = 4;
    public static final int FONT_FAMILY_CURSIVE = 5;
    public static final int FONT_FAMILY_MONOSPACED_SANS_SERIF = 1;
    public static final int FONT_FAMILY_MONOSPACED_SERIF = 3;
    public static final int FONT_FAMILY_SANS_SERIF = 0;
    public static final int FONT_FAMILY_SERIF = 2;
    public static final int FONT_FAMILY_SMALL_CAPITALS = 6;
    public static final int FONT_FAMILY_UNSPECIFIED = -1;
    public static final int FONT_STYLE_BOLD = 1;
    public static final int FONT_STYLE_BOLD_ITALIC = 3;
    public static final int FONT_STYLE_ITALIC = 2;
    public static final int FONT_STYLE_NORMAL = 0;
    public static final int FONT_STYLE_UNSPECIFIED = -1;
    public static final int WINDOW_TYPE_NONE = 0;
    public static final int WINDOW_TYPE_NORMAL = 1;
    public static final int WINDOW_TYPE_ROUNDED = 2;
    public static final int WINDOW_TYPE_UNSPECIFIED = -1;
    private JSONObject zzRJ;
    private float zzTc;
    private int zzTd;
    private int zzTe;
    private int zzTf;
    private int zzTg;
    private int zzTh;
    private int zzTi;
    private String zzTj;
    private int zzTk;
    private int zzTl;
    private int zzvc;

    public TextTrackStyle() {
        clear();
    }

    private void clear() {
        this.zzTc = 1.0f;
        this.zzTd = 0;
        this.zzvc = 0;
        this.zzTe = -1;
        this.zzTf = 0;
        this.zzTg = -1;
        this.zzTh = 0;
        this.zzTi = 0;
        this.zzTj = null;
        this.zzTk = -1;
        this.zzTl = -1;
        this.zzRJ = null;
    }

    public static TextTrackStyle fromSystemSettings(Context context) {
        TextTrackStyle textTrackStyle = new TextTrackStyle();
        if (zzlk.zzoX()) {
            CaptioningManager captioningManager = (CaptioningManager) context.getSystemService("captioning");
            textTrackStyle.setFontScale(captioningManager.getFontScale());
            CaptioningManager.CaptionStyle userStyle = captioningManager.getUserStyle();
            textTrackStyle.setBackgroundColor(userStyle.backgroundColor);
            textTrackStyle.setForegroundColor(userStyle.foregroundColor);
            switch (userStyle.edgeType) {
                case 1:
                    textTrackStyle.setEdgeType(1);
                    break;
                case 2:
                    textTrackStyle.setEdgeType(2);
                    break;
                default:
                    textTrackStyle.setEdgeType(0);
                    break;
            }
            textTrackStyle.setEdgeColor(userStyle.edgeColor);
            Typeface typeface = userStyle.getTypeface();
            if (typeface != null) {
                if (Typeface.MONOSPACE.equals(typeface)) {
                    textTrackStyle.setFontGenericFamily(1);
                } else if (Typeface.SANS_SERIF.equals(typeface)) {
                    textTrackStyle.setFontGenericFamily(0);
                } else if (Typeface.SERIF.equals(typeface)) {
                    textTrackStyle.setFontGenericFamily(2);
                } else {
                    textTrackStyle.setFontGenericFamily(0);
                }
                boolean isBold = typeface.isBold();
                boolean isItalic = typeface.isItalic();
                if (isBold && isItalic) {
                    textTrackStyle.setFontStyle(3);
                } else if (isBold) {
                    textTrackStyle.setFontStyle(1);
                } else if (isItalic) {
                    textTrackStyle.setFontStyle(2);
                } else {
                    textTrackStyle.setFontStyle(0);
                }
            }
            return textTrackStyle;
        }
        return textTrackStyle;
    }

    private String zzG(int i) {
        return String.format("#%02X%02X%02X%02X", Integer.valueOf(Color.red(i)), Integer.valueOf(Color.green(i)), Integer.valueOf(Color.blue(i)), Integer.valueOf(Color.alpha(i)));
    }

    private int zzbz(String str) {
        if (str != null && str.length() == 9 && str.charAt(0) == '#') {
            try {
                return Color.argb(Integer.parseInt(str.substring(7, 9), 16), Integer.parseInt(str.substring(1, 3), 16), Integer.parseInt(str.substring(3, 5), 16), Integer.parseInt(str.substring(5, 7), 16));
            } catch (NumberFormatException e) {
                return 0;
            }
        }
        return 0;
    }

    public boolean equals(Object other) {
        boolean z = true;
        if (this == other) {
            return true;
        }
        if (other instanceof TextTrackStyle) {
            TextTrackStyle textTrackStyle = (TextTrackStyle) other;
            if ((this.zzRJ == null) == (textTrackStyle.zzRJ == null)) {
                if (this.zzRJ == null || textTrackStyle.zzRJ == null || zzlh.zzd(this.zzRJ, textTrackStyle.zzRJ)) {
                    if (this.zzTc != textTrackStyle.zzTc || this.zzTd != textTrackStyle.zzTd || this.zzvc != textTrackStyle.zzvc || this.zzTe != textTrackStyle.zzTe || this.zzTf != textTrackStyle.zzTf || this.zzTg != textTrackStyle.zzTg || this.zzTi != textTrackStyle.zzTi || !zzf.zza(this.zzTj, textTrackStyle.zzTj) || this.zzTk != textTrackStyle.zzTk || this.zzTl != textTrackStyle.zzTl) {
                        z = false;
                    }
                    return z;
                }
                return false;
            }
            return false;
        }
        return false;
    }

    public int getBackgroundColor() {
        return this.zzvc;
    }

    public JSONObject getCustomData() {
        return this.zzRJ;
    }

    public int getEdgeColor() {
        return this.zzTf;
    }

    public int getEdgeType() {
        return this.zzTe;
    }

    public String getFontFamily() {
        return this.zzTj;
    }

    public int getFontGenericFamily() {
        return this.zzTk;
    }

    public float getFontScale() {
        return this.zzTc;
    }

    public int getFontStyle() {
        return this.zzTl;
    }

    public int getForegroundColor() {
        return this.zzTd;
    }

    public int getWindowColor() {
        return this.zzTh;
    }

    public int getWindowCornerRadius() {
        return this.zzTi;
    }

    public int getWindowType() {
        return this.zzTg;
    }

    public int hashCode() {
        return zzt.hashCode(Float.valueOf(this.zzTc), Integer.valueOf(this.zzTd), Integer.valueOf(this.zzvc), Integer.valueOf(this.zzTe), Integer.valueOf(this.zzTf), Integer.valueOf(this.zzTg), Integer.valueOf(this.zzTh), Integer.valueOf(this.zzTi), this.zzTj, Integer.valueOf(this.zzTk), Integer.valueOf(this.zzTl), this.zzRJ);
    }

    public void setBackgroundColor(int backgroundColor) {
        this.zzvc = backgroundColor;
    }

    public void setCustomData(JSONObject customData) {
        this.zzRJ = customData;
    }

    public void setEdgeColor(int edgeColor) {
        this.zzTf = edgeColor;
    }

    public void setEdgeType(int edgeType) {
        if (edgeType < 0 || edgeType > 4) {
            throw new IllegalArgumentException("invalid edgeType");
        }
        this.zzTe = edgeType;
    }

    public void setFontFamily(String fontFamily) {
        this.zzTj = fontFamily;
    }

    public void setFontGenericFamily(int fontGenericFamily) {
        if (fontGenericFamily < 0 || fontGenericFamily > 6) {
            throw new IllegalArgumentException("invalid fontGenericFamily");
        }
        this.zzTk = fontGenericFamily;
    }

    public void setFontScale(float fontScale) {
        this.zzTc = fontScale;
    }

    public void setFontStyle(int fontStyle) {
        if (fontStyle < 0 || fontStyle > 3) {
            throw new IllegalArgumentException("invalid fontStyle");
        }
        this.zzTl = fontStyle;
    }

    public void setForegroundColor(int foregroundColor) {
        this.zzTd = foregroundColor;
    }

    public void setWindowColor(int windowColor) {
        this.zzTh = windowColor;
    }

    public void setWindowCornerRadius(int windowCornerRadius) {
        if (windowCornerRadius < 0) {
            throw new IllegalArgumentException("invalid windowCornerRadius");
        }
        this.zzTi = windowCornerRadius;
    }

    public void setWindowType(int windowType) {
        if (windowType < 0 || windowType > 2) {
            throw new IllegalArgumentException("invalid windowType");
        }
        this.zzTg = windowType;
    }

    public JSONObject toJson() {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("fontScale", this.zzTc);
            if (this.zzTd != 0) {
                jSONObject.put("foregroundColor", zzG(this.zzTd));
            }
            if (this.zzvc != 0) {
                jSONObject.put("backgroundColor", zzG(this.zzvc));
            }
            switch (this.zzTe) {
                case 0:
                    jSONObject.put("edgeType", "NONE");
                    break;
                case 1:
                    jSONObject.put("edgeType", "OUTLINE");
                    break;
                case 2:
                    jSONObject.put("edgeType", "DROP_SHADOW");
                    break;
                case 3:
                    jSONObject.put("edgeType", "RAISED");
                    break;
                case 4:
                    jSONObject.put("edgeType", "DEPRESSED");
                    break;
            }
            if (this.zzTf != 0) {
                jSONObject.put("edgeColor", zzG(this.zzTf));
            }
            switch (this.zzTg) {
                case 0:
                    jSONObject.put("windowType", "NONE");
                    break;
                case 1:
                    jSONObject.put("windowType", "NORMAL");
                    break;
                case 2:
                    jSONObject.put("windowType", "ROUNDED_CORNERS");
                    break;
            }
            if (this.zzTh != 0) {
                jSONObject.put("windowColor", zzG(this.zzTh));
            }
            if (this.zzTg == 2) {
                jSONObject.put("windowRoundedCornerRadius", this.zzTi);
            }
            if (this.zzTj != null) {
                jSONObject.put("fontFamily", this.zzTj);
            }
            switch (this.zzTk) {
                case 0:
                    jSONObject.put("fontGenericFamily", "SANS_SERIF");
                    break;
                case 1:
                    jSONObject.put("fontGenericFamily", "MONOSPACED_SANS_SERIF");
                    break;
                case 2:
                    jSONObject.put("fontGenericFamily", "SERIF");
                    break;
                case 3:
                    jSONObject.put("fontGenericFamily", "MONOSPACED_SERIF");
                    break;
                case 4:
                    jSONObject.put("fontGenericFamily", "CASUAL");
                    break;
                case 5:
                    jSONObject.put("fontGenericFamily", "CURSIVE");
                    break;
                case 6:
                    jSONObject.put("fontGenericFamily", "SMALL_CAPITALS");
                    break;
            }
            switch (this.zzTl) {
                case 0:
                    jSONObject.put("fontStyle", "NORMAL");
                    break;
                case 1:
                    jSONObject.put("fontStyle", "BOLD");
                    break;
                case 2:
                    jSONObject.put("fontStyle", "ITALIC");
                    break;
                case 3:
                    jSONObject.put("fontStyle", "BOLD_ITALIC");
                    break;
            }
            if (this.zzRJ != null) {
                jSONObject.put("customData", this.zzRJ);
            }
        } catch (JSONException e) {
        }
        return jSONObject;
    }

    public void zzf(JSONObject jSONObject) throws JSONException {
        clear();
        this.zzTc = (float) jSONObject.optDouble("fontScale", 1.0d);
        this.zzTd = zzbz(jSONObject.optString("foregroundColor"));
        this.zzvc = zzbz(jSONObject.optString("backgroundColor"));
        if (jSONObject.has("edgeType")) {
            String string = jSONObject.getString("edgeType");
            if ("NONE".equals(string)) {
                this.zzTe = 0;
            } else if ("OUTLINE".equals(string)) {
                this.zzTe = 1;
            } else if ("DROP_SHADOW".equals(string)) {
                this.zzTe = 2;
            } else if ("RAISED".equals(string)) {
                this.zzTe = 3;
            } else if ("DEPRESSED".equals(string)) {
                this.zzTe = 4;
            }
        }
        this.zzTf = zzbz(jSONObject.optString("edgeColor"));
        if (jSONObject.has("windowType")) {
            String string2 = jSONObject.getString("windowType");
            if ("NONE".equals(string2)) {
                this.zzTg = 0;
            } else if ("NORMAL".equals(string2)) {
                this.zzTg = 1;
            } else if ("ROUNDED_CORNERS".equals(string2)) {
                this.zzTg = 2;
            }
        }
        this.zzTh = zzbz(jSONObject.optString("windowColor"));
        if (this.zzTg == 2) {
            this.zzTi = jSONObject.optInt("windowRoundedCornerRadius", 0);
        }
        this.zzTj = jSONObject.optString("fontFamily", null);
        if (jSONObject.has("fontGenericFamily")) {
            String string3 = jSONObject.getString("fontGenericFamily");
            if ("SANS_SERIF".equals(string3)) {
                this.zzTk = 0;
            } else if ("MONOSPACED_SANS_SERIF".equals(string3)) {
                this.zzTk = 1;
            } else if ("SERIF".equals(string3)) {
                this.zzTk = 2;
            } else if ("MONOSPACED_SERIF".equals(string3)) {
                this.zzTk = 3;
            } else if ("CASUAL".equals(string3)) {
                this.zzTk = 4;
            } else if ("CURSIVE".equals(string3)) {
                this.zzTk = 5;
            } else if ("SMALL_CAPITALS".equals(string3)) {
                this.zzTk = 6;
            }
        }
        if (jSONObject.has("fontStyle")) {
            String string4 = jSONObject.getString("fontStyle");
            if ("NORMAL".equals(string4)) {
                this.zzTl = 0;
            } else if ("BOLD".equals(string4)) {
                this.zzTl = 1;
            } else if ("ITALIC".equals(string4)) {
                this.zzTl = 2;
            } else if ("BOLD_ITALIC".equals(string4)) {
                this.zzTl = 3;
            }
        }
        this.zzRJ = jSONObject.optJSONObject("customData");
    }
}
