package com.google.android.gms.common.api;

import android.os.DeadObjectException;
import android.os.RemoteException;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.zzg;
import com.google.android.gms.common.internal.zzu;
import java.util.concurrent.atomic.AtomicReference;
/* loaded from: classes.dex */
public class zza {

    /* renamed from: com.google.android.gms.common.api.zza$zza  reason: collision with other inner class name */
    /* loaded from: classes.dex */
    public static abstract class AbstractC0032zza<R extends Result, A extends Api.Client> extends AbstractPendingResult<R> implements zzb<R>, zzg.zze<A> {
        private final Api.ClientKey<A> zzVu;
        private AtomicReference<zzg.zzc> zzWm;

        /* JADX INFO: Access modifiers changed from: protected */
        public AbstractC0032zza(Api.ClientKey<A> clientKey, GoogleApiClient googleApiClient) {
            super(((GoogleApiClient) zzu.zzb(googleApiClient, "GoogleApiClient must not be null")).getLooper());
            this.zzWm = new AtomicReference<>();
            this.zzVu = (Api.ClientKey) zzu.zzu(clientKey);
        }

        private void zza(RemoteException remoteException) {
            zzr(new Status(8, remoteException.getLocalizedMessage(), null));
        }

        @Override // com.google.android.gms.common.api.AbstractPendingResult
        protected void onResultConsumed() {
            zzg.zzc andSet = this.zzWm.getAndSet(null);
            if (andSet != null) {
                andSet.zzc(this);
            }
        }

        protected abstract void zza(A a) throws RemoteException;

        @Override // com.google.android.gms.common.api.zzg.zze
        public void zza(zzg.zzc zzcVar) {
            this.zzWm.set(zzcVar);
        }

        @Override // com.google.android.gms.common.api.zzg.zze
        public final void zzb(A a) throws DeadObjectException {
            try {
                zza((AbstractC0032zza<R, A>) a);
            } catch (DeadObjectException e) {
                zza(e);
                throw e;
            } catch (RemoteException e2) {
                zza(e2);
            }
        }

        /* JADX WARN: Multi-variable type inference failed */
        @Override // com.google.android.gms.common.api.zza.zzb
        public /* synthetic */ void zzm(Object obj) {
            super.setResult((Result) obj);
        }

        @Override // com.google.android.gms.common.api.zzg.zze
        public final Api.ClientKey<A> zzms() {
            return this.zzVu;
        }

        @Override // com.google.android.gms.common.api.zzg.zze
        public int zzmv() {
            return 0;
        }

        @Override // com.google.android.gms.common.api.zza.zzb, com.google.android.gms.common.api.zzg.zze
        public final void zzr(Status status) {
            zzu.zzb(!status.isSuccess(), "Failed result must not be success");
            setResult(createFailedResult(status));
        }
    }

    /* loaded from: classes.dex */
    public interface zzb<R> {
        void zzm(R r);

        void zzr(Status status);
    }
}
