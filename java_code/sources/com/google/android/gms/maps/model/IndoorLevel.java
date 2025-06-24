package com.google.android.gms.maps.model;

import android.os.RemoteException;
import com.google.android.gms.common.internal.zzu;
/* loaded from: classes.dex */
public final class IndoorLevel {
    private final com.google.android.gms.maps.model.internal.zzh zzaDm;

    public IndoorLevel(com.google.android.gms.maps.model.internal.zzh delegate) {
        this.zzaDm = (com.google.android.gms.maps.model.internal.zzh) zzu.zzu(delegate);
    }

    public void activate() {
        try {
            this.zzaDm.activate();
        } catch (RemoteException e) {
            throw new RuntimeRemoteException(e);
        }
    }

    public boolean equals(Object other) {
        if (other instanceof IndoorLevel) {
            try {
                return this.zzaDm.zza(((IndoorLevel) other).zzaDm);
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }
        return false;
    }

    public String getName() {
        try {
            return this.zzaDm.getName();
        } catch (RemoteException e) {
            throw new RuntimeRemoteException(e);
        }
    }

    public String getShortName() {
        try {
            return this.zzaDm.getShortName();
        } catch (RemoteException e) {
            throw new RuntimeRemoteException(e);
        }
    }

    public int hashCode() {
        try {
            return this.zzaDm.hashCodeRemote();
        } catch (RemoteException e) {
            throw new RuntimeRemoteException(e);
        }
    }
}
