package com.google.android.gms.ads.internal.formats;

import android.graphics.Color;
import android.graphics.drawable.Drawable;
/* loaded from: classes.dex */
public class zza {
    private static final int zzuW = Color.rgb(12, 174, 206);
    private static final int zzuX = Color.rgb(204, 204, 204);
    static final int zzuY = zzuX;
    static final int zzuZ = zzuW;
    private final int mTextColor;
    private final String zzva;
    private final Drawable zzvb;
    private final int zzvc;
    private final int zzvd;

    public zza(String str, Drawable drawable, Integer num, Integer num2, Integer num3) {
        this.zzva = str;
        this.zzvb = drawable;
        this.zzvc = num != null ? num.intValue() : zzuY;
        this.mTextColor = num2 != null ? num2.intValue() : zzuZ;
        this.zzvd = num3 != null ? num3.intValue() : 12;
    }

    public int getBackgroundColor() {
        return this.zzvc;
    }

    public Drawable getIcon() {
        return this.zzvb;
    }

    public String getText() {
        return this.zzva;
    }

    public int getTextSize() {
        return this.zzvd;
    }

    public int zzdu() {
        return this.mTextColor;
    }
}
