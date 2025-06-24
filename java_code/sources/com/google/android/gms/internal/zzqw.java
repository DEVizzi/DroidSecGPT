package com.google.android.gms.internal;

import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.wallet.FullWalletRequest;
import com.google.android.gms.wallet.MaskedWalletRequest;
import com.google.android.gms.wallet.NotifyTransactionStatusRequest;
import com.google.android.gms.wallet.Payments;
import com.google.android.gms.wallet.Wallet;
/* loaded from: classes.dex */
public class zzqw implements Payments {
    @Override // com.google.android.gms.wallet.Payments
    public void changeMaskedWallet(GoogleApiClient googleApiClient, final String googleTransactionId, final String merchantTransactionId, final int requestCode) {
        googleApiClient.zza((GoogleApiClient) new Wallet.zzb(googleApiClient) { // from class: com.google.android.gms.internal.zzqw.4
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzqx zzqxVar) {
                zzqxVar.zze(googleTransactionId, merchantTransactionId, requestCode);
                setResult(Status.zzXP);
            }
        });
    }

    @Override // com.google.android.gms.wallet.Payments
    public void checkForPreAuthorization(GoogleApiClient googleApiClient, final int requestCode) {
        googleApiClient.zza((GoogleApiClient) new Wallet.zzb(googleApiClient) { // from class: com.google.android.gms.internal.zzqw.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzqx zzqxVar) {
                zzqxVar.zzjB(requestCode);
                setResult(Status.zzXP);
            }
        });
    }

    @Override // com.google.android.gms.wallet.Payments
    public void isNewUser(GoogleApiClient googleApiClient, final int requestCode) {
        googleApiClient.zza((GoogleApiClient) new Wallet.zzb(googleApiClient) { // from class: com.google.android.gms.internal.zzqw.6
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzqx zzqxVar) {
                zzqxVar.zzjC(requestCode);
                setResult(Status.zzXP);
            }
        });
    }

    @Override // com.google.android.gms.wallet.Payments
    public void loadFullWallet(GoogleApiClient googleApiClient, final FullWalletRequest request, final int requestCode) {
        googleApiClient.zza((GoogleApiClient) new Wallet.zzb(googleApiClient) { // from class: com.google.android.gms.internal.zzqw.3
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzqx zzqxVar) {
                zzqxVar.zza(request, requestCode);
                setResult(Status.zzXP);
            }
        });
    }

    @Override // com.google.android.gms.wallet.Payments
    public void loadMaskedWallet(GoogleApiClient googleApiClient, final MaskedWalletRequest request, final int requestCode) {
        googleApiClient.zza((GoogleApiClient) new Wallet.zzb(googleApiClient) { // from class: com.google.android.gms.internal.zzqw.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzqx zzqxVar) {
                zzqxVar.zza(request, requestCode);
                setResult(Status.zzXP);
            }
        });
    }

    @Override // com.google.android.gms.wallet.Payments
    public void notifyTransactionStatus(GoogleApiClient googleApiClient, final NotifyTransactionStatusRequest request) {
        googleApiClient.zza((GoogleApiClient) new Wallet.zzb(googleApiClient) { // from class: com.google.android.gms.internal.zzqw.5
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzqx zzqxVar) {
                zzqxVar.zza(request);
                setResult(Status.zzXP);
            }
        });
    }
}
