package com.google.android.gms.wearable;
/* loaded from: classes.dex */
public interface MessageEvent {
    byte[] getData();

    String getPath();

    int getRequestId();

    String getSourceNodeId();
}
