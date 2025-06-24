package com.google.android.gms.internal;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.provider.CalendarContract;
import android.text.TextUtils;
import com.google.android.gms.R;
import com.google.android.gms.drive.DriveFile;
import com.google.android.gms.plus.PlusShare;
import java.util.Map;
@zzgd
/* loaded from: classes.dex */
public class zzeo extends zzeu {
    private final Context mContext;
    private final Map<String, String> zzyn;
    private String zzyo;
    private long zzyp;
    private long zzyq;
    private String zzyr;
    private String zzys;

    public zzeo(zzid zzidVar, Map<String, String> map) {
        super(zzidVar, "createCalendarEvent");
        this.zzyn = map;
        this.mContext = zzidVar.zzgB();
        zzeb();
    }

    private String zzab(String str) {
        return TextUtils.isEmpty(this.zzyn.get(str)) ? "" : this.zzyn.get(str);
    }

    private long zzac(String str) {
        String str2 = this.zzyn.get(str);
        if (str2 == null) {
            return -1L;
        }
        try {
            return Long.parseLong(str2);
        } catch (NumberFormatException e) {
            return -1L;
        }
    }

    private void zzeb() {
        this.zzyo = zzab(PlusShare.KEY_CONTENT_DEEP_LINK_METADATA_DESCRIPTION);
        this.zzyr = zzab("summary");
        this.zzyp = zzac("start_ticks");
        this.zzyq = zzac("end_ticks");
        this.zzys = zzab("location");
    }

    Intent createIntent() {
        Intent data = new Intent("android.intent.action.EDIT").setData(CalendarContract.Events.CONTENT_URI);
        data.putExtra(PlusShare.KEY_CONTENT_DEEP_LINK_METADATA_TITLE, this.zzyo);
        data.putExtra("eventLocation", this.zzys);
        data.putExtra(PlusShare.KEY_CONTENT_DEEP_LINK_METADATA_DESCRIPTION, this.zzyr);
        if (this.zzyp > -1) {
            data.putExtra("beginTime", this.zzyp);
        }
        if (this.zzyq > -1) {
            data.putExtra("endTime", this.zzyq);
        }
        data.setFlags(DriveFile.MODE_READ_ONLY);
        return data;
    }

    public void execute() {
        if (this.mContext == null) {
            zzae("Activity context is not available.");
        } else if (!com.google.android.gms.ads.internal.zzo.zzbv().zzK(this.mContext).zzcV()) {
            zzae("This feature is not available on the device.");
        } else {
            AlertDialog.Builder zzJ = com.google.android.gms.ads.internal.zzo.zzbv().zzJ(this.mContext);
            zzJ.setTitle(com.google.android.gms.ads.internal.zzo.zzby().zzc(R.string.create_calendar_title, "Create calendar event"));
            zzJ.setMessage(com.google.android.gms.ads.internal.zzo.zzby().zzc(R.string.create_calendar_message, "Allow Ad to create a calendar event?"));
            zzJ.setPositiveButton(com.google.android.gms.ads.internal.zzo.zzby().zzc(R.string.accept, "Accept"), new DialogInterface.OnClickListener() { // from class: com.google.android.gms.internal.zzeo.1
                @Override // android.content.DialogInterface.OnClickListener
                public void onClick(DialogInterface dialog, int which) {
                    zzeo.this.mContext.startActivity(zzeo.this.createIntent());
                }
            });
            zzJ.setNegativeButton(com.google.android.gms.ads.internal.zzo.zzby().zzc(R.string.decline, "Decline"), new DialogInterface.OnClickListener() { // from class: com.google.android.gms.internal.zzeo.2
                @Override // android.content.DialogInterface.OnClickListener
                public void onClick(DialogInterface dialog, int which) {
                    zzeo.this.zzae("Operation denied by user.");
                }
            });
            zzJ.create().show();
        }
    }
}
