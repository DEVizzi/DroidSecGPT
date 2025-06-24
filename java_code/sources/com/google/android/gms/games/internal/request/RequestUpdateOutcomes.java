package com.google.android.gms.games.internal.request;

import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.games.internal.constants.RequestUpdateResultOutcome;
import java.util.HashMap;
import java.util.Set;
/* loaded from: classes.dex */
public final class RequestUpdateOutcomes {
    private static final String[] zzatw = {"requestId", "outcome"};
    private final int zzTS;
    private final HashMap<String, Integer> zzatx;

    /* loaded from: classes.dex */
    public static final class Builder {
        private HashMap<String, Integer> zzatx = new HashMap<>();
        private int zzTS = 0;

        public Builder zzfQ(int i) {
            this.zzTS = i;
            return this;
        }

        public RequestUpdateOutcomes zztD() {
            return new RequestUpdateOutcomes(this.zzTS, this.zzatx);
        }

        public Builder zzx(String str, int i) {
            if (RequestUpdateResultOutcome.isValid(i)) {
                this.zzatx.put(str, Integer.valueOf(i));
            }
            return this;
        }
    }

    private RequestUpdateOutcomes(int statusCode, HashMap<String, Integer> outcomeMap) {
        this.zzTS = statusCode;
        this.zzatx = outcomeMap;
    }

    public static RequestUpdateOutcomes zzX(DataHolder dataHolder) {
        Builder builder = new Builder();
        builder.zzfQ(dataHolder.getStatusCode());
        int count = dataHolder.getCount();
        for (int i = 0; i < count; i++) {
            int zzbh = dataHolder.zzbh(i);
            builder.zzx(dataHolder.zzd("requestId", i, zzbh), dataHolder.zzc("outcome", i, zzbh));
        }
        return builder.zztD();
    }

    public Set<String> getRequestIds() {
        return this.zzatx.keySet();
    }

    public int getRequestOutcome(String requestId) {
        zzu.zzb(this.zzatx.containsKey(requestId), "Request " + requestId + " was not part of the update operation!");
        return this.zzatx.get(requestId).intValue();
    }
}
