package com.google.android.gms.tagmanager;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
/* loaded from: classes.dex */
public class PreviewActivity extends Activity {
    private void zzj(String str, String str2, String str3) {
        AlertDialog create = new AlertDialog.Builder(this).create();
        create.setTitle(str);
        create.setMessage(str2);
        create.setButton(-1, str3, new DialogInterface.OnClickListener() { // from class: com.google.android.gms.tagmanager.PreviewActivity.1
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialog, int which) {
            }
        });
        create.show();
    }

    @Override // android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        try {
            super.onCreate(savedInstanceState);
            zzbg.zzaA("Preview activity");
            Uri data = getIntent().getData();
            if (!TagManager.getInstance(this).zzl(data)) {
                String str = "Cannot preview the app with the uri: " + data + ". Launching current version instead.";
                zzbg.zzaC(str);
                zzj("Preview failure", str, "Continue");
            }
            Intent launchIntentForPackage = getPackageManager().getLaunchIntentForPackage(getPackageName());
            if (launchIntentForPackage == null) {
                zzbg.zzaA("No launch activity found for package name: " + getPackageName());
                return;
            }
            zzbg.zzaA("Invoke the launch activity for package name: " + getPackageName());
            startActivity(launchIntentForPackage);
        } catch (Exception e) {
            zzbg.zzaz("Calling preview threw an exception: " + e.getMessage());
        }
    }
}
