package com.google.android.gms.ads.internal.formats;

import android.content.Context;
import android.graphics.Typeface;
import android.graphics.drawable.ShapeDrawable;
import android.graphics.drawable.shapes.RoundRectShape;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import com.google.android.gms.ads.internal.client.zzk;
import com.google.android.gms.ads.internal.zzo;
import com.google.android.gms.common.internal.zzu;
/* loaded from: classes.dex */
class zzb extends RelativeLayout {
    private static final float[] zzve = {5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f};
    private final RelativeLayout zzvf;

    public zzb(Context context, zza zzaVar) {
        super(context);
        zzu.zzu(zzaVar);
        RelativeLayout.LayoutParams layoutParams = new RelativeLayout.LayoutParams(-2, -2);
        layoutParams.addRule(10);
        layoutParams.addRule(11);
        ShapeDrawable shapeDrawable = new ShapeDrawable(new RoundRectShape(zzve, null, null));
        shapeDrawable.getPaint().setColor(zzaVar.getBackgroundColor());
        this.zzvf = new RelativeLayout(context);
        this.zzvf.setLayoutParams(layoutParams);
        zzo.zzbx().zza(this.zzvf, shapeDrawable);
        RelativeLayout.LayoutParams layoutParams2 = new RelativeLayout.LayoutParams(-2, -2);
        TextView textView = new TextView(context);
        textView.setLayoutParams(layoutParams2);
        textView.setId(1195835393);
        textView.setTypeface(Typeface.DEFAULT);
        textView.setText(zzaVar.getText());
        textView.setTextColor(zzaVar.zzdu());
        textView.setTextSize(zzaVar.getTextSize());
        textView.setPadding(zzk.zzcA().zzb(context, 4), 0, zzk.zzcA().zzb(context, 4), 0);
        RelativeLayout.LayoutParams layoutParams3 = new RelativeLayout.LayoutParams(-2, -2);
        layoutParams3.addRule(1, textView.getId());
        ImageView imageView = new ImageView(context);
        imageView.setLayoutParams(layoutParams3);
        imageView.setId(1195835394);
        imageView.setImageDrawable(zzaVar.getIcon());
        this.zzvf.addView(textView);
        this.zzvf.addView(imageView);
        addView(this.zzvf);
    }

    public ViewGroup zzdv() {
        return this.zzvf;
    }
}
