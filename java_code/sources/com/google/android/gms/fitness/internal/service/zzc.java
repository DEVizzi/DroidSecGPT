package com.google.android.gms.fitness.internal.service;

import android.os.Binder;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.fitness.service.FitnessSensorServiceRequest;
import com.google.android.gms.internal.zzmg;
import com.google.android.gms.internal.zzmu;
/* loaded from: classes.dex */
public interface zzc extends IInterface {

    /* loaded from: classes.dex */
    public static abstract class zza extends Binder implements zzc {
        public zza() {
            attachInterface(this, "com.google.android.gms.fitness.internal.service.IFitnessSensorService");
        }

        @Override // android.os.IInterface
        public IBinder asBinder() {
            return this;
        }

        @Override // android.os.Binder
        public boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
            switch (code) {
                case 1:
                    data.enforceInterface("com.google.android.gms.fitness.internal.service.IFitnessSensorService");
                    zza(data.readInt() != 0 ? FitnessDataSourcesRequest.CREATOR.createFromParcel(data) : null, zzmg.zza.zzbr(data.readStrongBinder()));
                    return true;
                case 2:
                    data.enforceInterface("com.google.android.gms.fitness.internal.service.IFitnessSensorService");
                    zza(data.readInt() != 0 ? FitnessSensorServiceRequest.CREATOR.createFromParcel(data) : null, zzmu.zza.zzbF(data.readStrongBinder()));
                    return true;
                case 3:
                    data.enforceInterface("com.google.android.gms.fitness.internal.service.IFitnessSensorService");
                    zza(data.readInt() != 0 ? FitnessUnregistrationRequest.CREATOR.createFromParcel(data) : null, zzmu.zza.zzbF(data.readStrongBinder()));
                    return true;
                case 1598968902:
                    reply.writeString("com.google.android.gms.fitness.internal.service.IFitnessSensorService");
                    return true;
                default:
                    return super.onTransact(code, data, reply, flags);
            }
        }
    }

    void zza(FitnessDataSourcesRequest fitnessDataSourcesRequest, zzmg zzmgVar) throws RemoteException;

    void zza(FitnessUnregistrationRequest fitnessUnregistrationRequest, zzmu zzmuVar) throws RemoteException;

    void zza(FitnessSensorServiceRequest fitnessSensorServiceRequest, zzmu zzmuVar) throws RemoteException;
}
