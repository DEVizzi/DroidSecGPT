package com.google.android.gms.fitness;

import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.safeparcel.zzc;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.fitness.data.Session;
import com.google.android.gms.fitness.request.SessionInsertRequest;
import com.google.android.gms.fitness.request.SessionReadRequest;
import com.google.android.gms.fitness.result.SessionReadResult;
import com.google.android.gms.fitness.result.SessionStopResult;
/* loaded from: classes.dex */
public interface SessionsApi {

    /* loaded from: classes.dex */
    public static class ViewIntentBuilder {
        private final Context mContext;
        private String zzajI;
        private Session zzajJ;
        private boolean zzajK = false;

        public ViewIntentBuilder(Context context) {
            this.mContext = context;
        }

        private Intent zzj(Intent intent) {
            Intent intent2;
            ResolveInfo resolveActivity;
            if (this.zzajI == null || (resolveActivity = this.mContext.getPackageManager().resolveActivity((intent2 = new Intent(intent).setPackage(this.zzajI)), 0)) == null) {
                return intent;
            }
            intent2.setComponent(new ComponentName(this.zzajI, resolveActivity.activityInfo.name));
            return intent2;
        }

        public Intent build() {
            zzu.zza(this.zzajJ != null, "Session must be set");
            Intent intent = new Intent(Fitness.ACTION_VIEW);
            intent.setType(Session.getMimeType(this.zzajJ.getActivity()));
            zzc.zza(this.zzajJ, intent, Session.EXTRA_SESSION);
            if (!this.zzajK) {
                this.zzajI = this.zzajJ.getAppPackageName();
            }
            return zzj(intent);
        }

        public ViewIntentBuilder setPreferredApplication(String packageName) {
            this.zzajI = packageName;
            this.zzajK = true;
            return this;
        }

        public ViewIntentBuilder setSession(Session session) {
            this.zzajJ = session;
            return this;
        }
    }

    PendingResult<Status> insertSession(GoogleApiClient googleApiClient, SessionInsertRequest sessionInsertRequest);

    PendingResult<SessionReadResult> readSession(GoogleApiClient googleApiClient, SessionReadRequest sessionReadRequest);

    PendingResult<Status> registerForSessions(GoogleApiClient googleApiClient, PendingIntent pendingIntent);

    PendingResult<Status> startSession(GoogleApiClient googleApiClient, Session session);

    PendingResult<SessionStopResult> stopSession(GoogleApiClient googleApiClient, String str);

    PendingResult<Status> unregisterForSessions(GoogleApiClient googleApiClient, PendingIntent pendingIntent);
}
