package com.google.android.gms.wearable;

import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
/* loaded from: classes.dex */
public interface MessageApi {
    public static final int UNKNOWN_REQUEST_ID = -1;

    /* loaded from: classes.dex */
    public interface MessageListener {
        void onMessageReceived(MessageEvent messageEvent);
    }

    /* loaded from: classes.dex */
    public interface SendMessageResult extends Result {
        int getRequestId();
    }

    PendingResult<Status> addListener(GoogleApiClient googleApiClient, MessageListener messageListener);

    PendingResult<Status> removeListener(GoogleApiClient googleApiClient, MessageListener messageListener);

    PendingResult<SendMessageResult> sendMessage(GoogleApiClient googleApiClient, String str, String str2, byte[] bArr);
}
