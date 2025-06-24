package com.google.android.gms.fitness.service;

import android.os.RemoteException;
import com.google.android.gms.fitness.data.DataPoint;
import java.util.List;
/* loaded from: classes.dex */
public interface SensorEventDispatcher {
    void publish(DataPoint dataPoint) throws RemoteException;

    void publish(List<DataPoint> list) throws RemoteException;
}
