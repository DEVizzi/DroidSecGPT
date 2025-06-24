package com.google.android.gms.identity.intents;

import android.app.Activity;
import android.content.Context;
import android.os.Looper;
import android.os.RemoteException;
import android.support.v7.internal.widget.ActivityChooserView;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.common.internal.zze;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.internal.zznk;
/* loaded from: classes.dex */
public final class Address {
    static final Api.ClientKey<zznk> zzNX = new Api.ClientKey<>();
    private static final Api.zza<zznk, AddressOptions> zzNY = new Api.zza<zznk, AddressOptions>() { // from class: com.google.android.gms.identity.intents.Address.1
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        public zznk zza(Context context, Looper looper, zze zzeVar, AddressOptions addressOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            zzu.zzb(context instanceof Activity, "An Activity must be used for Address APIs");
            if (addressOptions == null) {
                addressOptions = new AddressOptions();
            }
            return new zznk((Activity) context, looper, connectionCallbacks, onConnectionFailedListener, zzeVar.getAccountName(), addressOptions.theme);
        }
    };
    public static final Api<AddressOptions> API = new Api<>("Address.API", zzNY, zzNX, new Scope[0]);

    /* loaded from: classes.dex */
    public static final class AddressOptions implements Api.ApiOptions.HasOptions {
        public final int theme;

        public AddressOptions() {
            this.theme = 0;
        }

        public AddressOptions(int theme) {
            this.theme = theme;
        }
    }

    /* loaded from: classes.dex */
    private static abstract class zza extends zza.AbstractC0032zza<Status, zznk> {
        public zza(GoogleApiClient googleApiClient) {
            super(Address.zzNX, googleApiClient);
        }

        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzb */
        public Status createFailedResult(Status status) {
            return status;
        }
    }

    public static void requestUserAddress(GoogleApiClient googleApiClient, final UserAddressRequest request, final int requestCode) {
        googleApiClient.zza((GoogleApiClient) new zza(googleApiClient) { // from class: com.google.android.gms.identity.intents.Address.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zznk zznkVar) throws RemoteException {
                zznkVar.zza(request, requestCode);
                setResult(Status.zzXP);
            }
        });
    }
}
