package com.google.android.gms.games.appcontent;

import android.net.Uri;
import android.os.Bundle;
import android.os.Parcelable;
import com.google.android.gms.common.data.Freezable;
/* loaded from: classes.dex */
public interface AppContentAnnotation extends Parcelable, Freezable<AppContentAnnotation> {
    String getDescription();

    String getId();

    String getTitle();

    String zzrS();

    int zzrT();

    Uri zzrU();

    Bundle zzrV();

    int zzrW();

    String zzrX();
}
