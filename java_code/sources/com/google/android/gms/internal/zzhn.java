package com.google.android.gms.internal;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.text.TextUtils;
import android.view.MotionEvent;
import java.util.Map;
@zzgd
/* loaded from: classes.dex */
public class zzhn {
    private final Context mContext;
    private int mState;
    private String zzGo;
    private float zzGp;
    private float zzGq;
    private float zzGr;
    private final float zzyV;

    public zzhn(Context context) {
        this.mState = 0;
        this.mContext = context;
        this.zzyV = context.getResources().getDisplayMetrics().density;
    }

    public zzhn(Context context, String str) {
        this(context);
        this.zzGo = str;
    }

    private void showDialog() {
        final String str;
        if (!(this.mContext instanceof Activity)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaA("Can not create dialog without Activity Context");
            return;
        }
        if (TextUtils.isEmpty(this.zzGo)) {
            str = "No debug information";
        } else {
            Uri build = new Uri.Builder().encodedQuery(this.zzGo).build();
            StringBuilder sb = new StringBuilder();
            Map<String, String> zzd = com.google.android.gms.ads.internal.zzo.zzbv().zzd(build);
            for (String str2 : zzd.keySet()) {
                sb.append(str2).append(" = ").append(zzd.get(str2)).append("\n\n");
            }
            str = sb.toString().trim();
            if (TextUtils.isEmpty(str)) {
                str = "No debug information";
            }
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(this.mContext);
        builder.setMessage(str);
        builder.setTitle("Ad Information");
        builder.setPositiveButton("Share", new DialogInterface.OnClickListener() { // from class: com.google.android.gms.internal.zzhn.1
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialog, int which) {
                zzhn.this.mContext.startActivity(Intent.createChooser(new Intent("android.intent.action.SEND").setType("text/plain").putExtra("android.intent.extra.TEXT", str), "Share via"));
            }
        });
        builder.setNegativeButton("Close", new DialogInterface.OnClickListener() { // from class: com.google.android.gms.internal.zzhn.2
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialog, int which) {
            }
        });
        builder.create().show();
    }

    void zza(int i, float f, float f2) {
        if (i == 0) {
            this.mState = 0;
            this.zzGp = f;
            this.zzGq = f2;
            this.zzGr = f2;
        } else if (this.mState != -1) {
            if (i != 2) {
                if (i == 1 && this.mState == 4) {
                    showDialog();
                    return;
                }
                return;
            }
            if (f2 > this.zzGq) {
                this.zzGq = f2;
            } else if (f2 < this.zzGr) {
                this.zzGr = f2;
            }
            if (this.zzGq - this.zzGr > 30.0f * this.zzyV) {
                this.mState = -1;
                return;
            }
            if (this.mState == 0 || this.mState == 2) {
                if (f - this.zzGp >= 50.0f * this.zzyV) {
                    this.zzGp = f;
                    this.mState++;
                }
            } else if ((this.mState == 1 || this.mState == 3) && f - this.zzGp <= (-50.0f) * this.zzyV) {
                this.zzGp = f;
                this.mState++;
            }
            if (this.mState == 1 || this.mState == 3) {
                if (f > this.zzGp) {
                    this.zzGp = f;
                }
            } else if (this.mState != 2 || f >= this.zzGp) {
            } else {
                this.zzGp = f;
            }
        }
    }

    public void zzaw(String str) {
        this.zzGo = str;
    }

    public void zzd(MotionEvent motionEvent) {
        int historySize = motionEvent.getHistorySize();
        for (int i = 0; i < historySize; i++) {
            zza(motionEvent.getActionMasked(), motionEvent.getHistoricalX(0, i), motionEvent.getHistoricalY(0, i));
        }
        zza(motionEvent.getActionMasked(), motionEvent.getX(), motionEvent.getY());
    }
}
