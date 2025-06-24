package com.google.android.gms.internal;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;
import com.google.android.gms.cast.Cast;
import com.google.android.gms.cast.CastDevice;
import com.google.android.gms.cast.games.GameManagerClient;
import com.google.android.gms.cast.games.GameManagerState;
import com.google.android.gms.cast.games.PlayerInfo;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.ResultCallback;
import com.google.android.gms.common.api.Status;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.json.JSONException;
import org.json.JSONObject;
/* loaded from: classes.dex */
public class zzjs extends com.google.android.gms.cast.internal.zzc {
    static final String NAMESPACE = com.google.android.gms.cast.internal.zzf.zzbE("com.google.cast.games");
    private static final com.google.android.gms.cast.internal.zzl zzQW = new com.google.android.gms.cast.internal.zzl("GameManagerChannel");
    private String zzTA;
    private final Map<String, String> zzTn;
    private final List<com.google.android.gms.cast.internal.zzp> zzTo;
    private final String zzTp;
    private final Cast.CastApi zzTq;
    private final GoogleApiClient zzTr;
    private zzjt zzTs;
    private boolean zzTt;
    private GameManagerState zzTu;
    private GameManagerState zzTv;
    private String zzTw;
    private JSONObject zzTx;
    private long zzTy;
    private GameManagerClient.Listener zzTz;
    private final SharedPreferences zztB;

    /* loaded from: classes.dex */
    public abstract class zza extends zzb<GameManagerClient.GameManagerResult> {
        public zza() {
            super();
            this.zzTa = new com.google.android.gms.cast.internal.zzo() { // from class: com.google.android.gms.internal.zzjs.zza.1
                @Override // com.google.android.gms.cast.internal.zzo
                public void zza(long j, int i, Object obj) {
                    try {
                        if (obj == null) {
                            zza.this.setResult(new zze(new Status(i, null, null), null, j, null));
                            return;
                        }
                        zzju zzjuVar = (zzju) obj;
                        String playerId = zzjuVar.getPlayerId();
                        if (i == 0 && playerId != null) {
                            zzjs.this.zzTA = playerId;
                        }
                        zza.this.setResult(new zze(new Status(i, zzjuVar.zzlD(), null), playerId, zzjuVar.getRequestId(), zzjuVar.getExtraMessageData()));
                    } catch (ClassCastException e) {
                        zza.this.setResult(zza.this.createFailedResult(new Status(13)));
                    }
                }

                @Override // com.google.android.gms.cast.internal.zzo
                public void zzy(long j) {
                    zza.this.setResult(zza.this.createFailedResult(new Status(2103)));
                }
            };
        }

        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzo */
        public GameManagerClient.GameManagerResult createFailedResult(Status status) {
            return new zze(status, null, -1L, null);
        }
    }

    /* loaded from: classes.dex */
    public abstract class zzb<R extends Result> extends com.google.android.gms.cast.internal.zzb<R> {
        protected com.google.android.gms.cast.internal.zzo zzTa;

        public zzb() {
            super(zzjs.this.zzTr);
        }

        public abstract void execute();

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
        public void zza(com.google.android.gms.cast.internal.zze zzeVar) {
            execute();
        }

        public com.google.android.gms.cast.internal.zzo zzlA() {
            return this.zzTa;
        }
    }

    /* loaded from: classes.dex */
    public abstract class zzc extends zzb<GameManagerClient.GameManagerInstanceResult> {
        private GameManagerClient zzTJ;

        public zzc(GameManagerClient gameManagerClient) {
            super();
            this.zzTJ = gameManagerClient;
            this.zzTa = new com.google.android.gms.cast.internal.zzo() { // from class: com.google.android.gms.internal.zzjs.zzc.1
                @Override // com.google.android.gms.cast.internal.zzo
                public void zza(long j, int i, Object obj) {
                    try {
                        if (obj == null) {
                            zzc.this.setResult(new zzd(new Status(i, null, null), zzc.this.zzTJ));
                        } else {
                            zzju zzjuVar = (zzju) obj;
                            zzjt zzlH = zzjuVar.zzlH();
                            if (zzlH == null || com.google.android.gms.cast.internal.zzf.zza("1.0.0", zzlH.getVersion())) {
                                zzc.this.setResult(new zzd(new Status(i, zzjuVar.zzlD(), null), zzc.this.zzTJ));
                            } else {
                                zzc.this.setResult(zzc.this.createFailedResult(new Status(GameManagerClient.STATUS_INCORRECT_VERSION, String.format(Locale.ROOT, "Incorrect Game Manager SDK version. Receiver: %s Sender: %s", zzlH.getVersion(), "1.0.0"))));
                                zzjs.this.zzTs = null;
                            }
                        }
                    } catch (ClassCastException e) {
                        zzc.this.setResult(zzc.this.createFailedResult(new Status(13)));
                    }
                }

                @Override // com.google.android.gms.cast.internal.zzo
                public void zzy(long j) {
                    zzc.this.setResult(zzc.this.createFailedResult(new Status(2103)));
                }
            };
        }

        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzp */
        public GameManagerClient.GameManagerInstanceResult createFailedResult(Status status) {
            return new zzd(status, null);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static final class zzd implements GameManagerClient.GameManagerInstanceResult {
        private final Status zzOt;
        private final GameManagerClient zzTJ;

        zzd(Status status, GameManagerClient gameManagerClient) {
            this.zzOt = status;
            this.zzTJ = gameManagerClient;
        }

        @Override // com.google.android.gms.cast.games.GameManagerClient.GameManagerInstanceResult
        public GameManagerClient getGameManagerClient() {
            return this.zzTJ;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static final class zze implements GameManagerClient.GameManagerResult {
        private final Status zzOt;
        private final String zzTL;
        private final long zzTM;
        private final JSONObject zzTN;

        zze(Status status, String str, long j, JSONObject jSONObject) {
            this.zzOt = status;
            this.zzTL = str;
            this.zzTM = j;
            this.zzTN = jSONObject;
        }

        @Override // com.google.android.gms.cast.games.GameManagerClient.GameManagerResult
        public JSONObject getExtraMessageData() {
            return this.zzTN;
        }

        @Override // com.google.android.gms.cast.games.GameManagerClient.GameManagerResult
        public String getPlayerId() {
            return this.zzTL;
        }

        @Override // com.google.android.gms.cast.games.GameManagerClient.GameManagerResult
        public long getRequestId() {
            return this.zzTM;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }
    }

    public zzjs(GoogleApiClient googleApiClient, String str, Cast.CastApi castApi) throws IllegalArgumentException, IllegalStateException {
        super(NAMESPACE, "CastGameManagerChannel", null);
        this.zzTn = new ConcurrentHashMap();
        this.zzTt = false;
        this.zzTy = 0L;
        if (TextUtils.isEmpty(str)) {
            throw new IllegalArgumentException("castSessionId cannot be null.");
        }
        if (googleApiClient == null || !googleApiClient.isConnected() || !googleApiClient.hasConnectedApi(Cast.API)) {
            throw new IllegalArgumentException("googleApiClient needs to be connected and contain the Cast.API API.");
        }
        this.zzTo = new ArrayList();
        this.zzTp = str;
        this.zzTq = castApi;
        this.zzTr = googleApiClient;
        Context applicationContext = googleApiClient.getContext().getApplicationContext();
        this.zztB = applicationContext.getApplicationContext().getSharedPreferences(String.format(Locale.ROOT, "%s.%s", applicationContext.getPackageName(), "game_manager_channel_data"), 0);
        this.zzTv = null;
        this.zzTu = new zzjw(0, 0, "", null, new ArrayList(), "", -1);
    }

    private JSONObject zza(long j, String str, int i, JSONObject jSONObject) {
        try {
            JSONObject jSONObject2 = new JSONObject();
            jSONObject2.put("requestId", j);
            jSONObject2.put("type", i);
            jSONObject2.put("extraMessageData", jSONObject);
            jSONObject2.put("playerId", str);
            jSONObject2.put("playerToken", zzbA(str));
            return jSONObject2;
        } catch (JSONException e) {
            zzQW.zzf("JSONException when trying to create a message: %s", e.getMessage());
            return null;
        }
    }

    private synchronized void zza(zzju zzjuVar) {
        synchronized (this) {
            boolean z = zzjuVar.zzlC() == 1;
            this.zzTv = this.zzTu;
            if (z && zzjuVar.zzlH() != null) {
                this.zzTs = zzjuVar.zzlH();
            }
            if (isInitialized()) {
                ArrayList arrayList = new ArrayList();
                for (zzjy zzjyVar : zzjuVar.zzlE()) {
                    String playerId = zzjyVar.getPlayerId();
                    arrayList.add(new zzjx(playerId, zzjyVar.getPlayerState(), zzjyVar.getPlayerData(), this.zzTn.containsKey(playerId)));
                }
                this.zzTu = new zzjw(zzjuVar.getLobbyState(), zzjuVar.getGameplayState(), zzjuVar.zzlF(), zzjuVar.getGameData(), arrayList, this.zzTs.zzlB(), this.zzTs.getMaxPlayers());
                PlayerInfo player = this.zzTu.getPlayer(zzjuVar.getPlayerId());
                if (player != null && player.isControllable() && zzjuVar.zzlC() == 2) {
                    this.zzTw = zzjuVar.getPlayerId();
                    this.zzTx = zzjuVar.getExtraMessageData();
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zza(String str, int i, JSONObject jSONObject, com.google.android.gms.cast.internal.zzo zzoVar) {
        final long j = 1 + this.zzTy;
        this.zzTy = j;
        JSONObject zza2 = zza(j, str, i, jSONObject);
        if (zza2 == null) {
            zzoVar.zza(-1L, 2001, null);
            zzQW.zzf("Not sending request because it was invalid.", new Object[0]);
            return;
        }
        com.google.android.gms.cast.internal.zzp zzpVar = new com.google.android.gms.cast.internal.zzp(30000L);
        zzpVar.zza(j, zzoVar);
        this.zzTo.add(zzpVar);
        zzQ(true);
        this.zzTq.sendMessage(this.zzTr, getNamespace(), zza2.toString()).setResultCallback(new ResultCallback<Status>() { // from class: com.google.android.gms.internal.zzjs.4
            @Override // com.google.android.gms.common.api.ResultCallback
            /* renamed from: zzm */
            public void onResult(Status status) {
                if (status.isSuccess()) {
                    return;
                }
                zzjs.this.zzb(j, status.getStatusCode());
            }
        });
    }

    private int zzaI(int i) {
        switch (i) {
            case 0:
                return 0;
            case 1:
                return 2001;
            case 2:
                return 2003;
            case 3:
                return GameManagerClient.STATUS_INCORRECT_VERSION;
            case 4:
                return GameManagerClient.STATUS_TOO_MANY_PLAYERS;
            default:
                zzQW.zzf("Unknown GameManager protocol status code: " + i, new Object[0]);
                return 13;
        }
    }

    private void zzb(long j, int i, Object obj) {
        Iterator<com.google.android.gms.cast.internal.zzp> it = this.zzTo.iterator();
        while (it.hasNext()) {
            if (it.next().zzc(j, i, obj)) {
                it.remove();
            }
        }
    }

    private synchronized void zzlv() throws IllegalStateException {
        if (!isInitialized()) {
            throw new IllegalStateException("Attempted to perform an operation on the GameManagerChannel before it is initialized.");
        }
        if (isDisposed()) {
            throw new IllegalStateException("Attempted to perform an operation on the GameManagerChannel after it has been disposed.");
        }
    }

    private void zzlw() {
        if (this.zzTz != null) {
            if (this.zzTv != null && !this.zzTu.equals(this.zzTv)) {
                this.zzTz.onStateChanged(this.zzTu, this.zzTv);
            }
            if (this.zzTx != null && this.zzTw != null) {
                this.zzTz.onGameMessageReceived(this.zzTw, this.zzTx);
            }
        }
        this.zzTv = null;
        this.zzTw = null;
        this.zzTx = null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public synchronized void zzlx() {
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("castSessionId", this.zzTp);
            jSONObject.put("playerTokenMap", new JSONObject(this.zzTn));
            this.zztB.edit().putString("save_data", jSONObject.toString()).commit();
        } catch (JSONException e) {
            zzQW.zzf("Error while saving data: %s", e.getMessage());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public synchronized void zzly() {
        String string = this.zztB.getString("save_data", null);
        if (string != null) {
            try {
                JSONObject jSONObject = new JSONObject(string);
                if (this.zzTp.equals(jSONObject.getString("castSessionId"))) {
                    JSONObject jSONObject2 = jSONObject.getJSONObject("playerTokenMap");
                    Iterator<String> keys = jSONObject2.keys();
                    while (keys.hasNext()) {
                        String next = keys.next();
                        this.zzTn.put(next, jSONObject2.getString(next));
                    }
                    this.zzTy = 0L;
                }
            } catch (JSONException e) {
                zzQW.zzf("Error while loading data: %s", e.getMessage());
            }
        }
    }

    public synchronized void dispose() throws IllegalStateException {
        if (!this.zzTt) {
            this.zzTu = null;
            this.zzTv = null;
            this.zzTw = null;
            this.zzTx = null;
            this.zzTt = true;
            try {
                this.zzTq.removeMessageReceivedCallbacks(this.zzTr, getNamespace());
            } catch (IOException e) {
                zzQW.zzf("Exception while detaching game manager channel.", e);
            }
        }
    }

    public synchronized GameManagerState getCurrentState() throws IllegalStateException {
        zzlv();
        return this.zzTu;
    }

    public synchronized String getLastUsedPlayerId() throws IllegalStateException {
        zzlv();
        return this.zzTA;
    }

    public synchronized boolean isDisposed() {
        return this.zzTt;
    }

    public synchronized boolean isInitialized() {
        return this.zzTs != null;
    }

    public synchronized void sendGameMessage(String playerId, JSONObject extraMessageData) throws IllegalStateException {
        zzlv();
        long j = 1 + this.zzTy;
        this.zzTy = j;
        JSONObject zza2 = zza(j, playerId, 7, extraMessageData);
        if (zza2 != null) {
            this.zzTq.sendMessage(this.zzTr, getNamespace(), zza2.toString());
        }
    }

    public synchronized PendingResult<GameManagerClient.GameManagerResult> sendGameRequest(final String playerId, final JSONObject extraMessageData) throws IllegalStateException {
        zzlv();
        return this.zzTr.zzb(new zza() { // from class: com.google.android.gms.internal.zzjs.3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super();
            }

            @Override // com.google.android.gms.internal.zzjs.zzb
            public void execute() {
                zzjs.this.zza(playerId, 6, extraMessageData, zzlA());
            }
        });
    }

    public synchronized void setListener(GameManagerClient.Listener listener) {
        this.zzTz = listener;
    }

    public synchronized PendingResult<GameManagerClient.GameManagerInstanceResult> zza(GameManagerClient gameManagerClient) throws IllegalArgumentException {
        if (gameManagerClient == null) {
            throw new IllegalArgumentException("gameManagerClient can't be null.");
        }
        return this.zzTr.zzb(new zzc(gameManagerClient) { // from class: com.google.android.gms.internal.zzjs.1
            @Override // com.google.android.gms.internal.zzjs.zzb
            public void execute() {
                try {
                    zzjs.this.zzTq.setMessageReceivedCallbacks(zzjs.this.zzTr, zzjs.this.getNamespace(), new Cast.MessageReceivedCallback() { // from class: com.google.android.gms.internal.zzjs.1.1
                        @Override // com.google.android.gms.cast.Cast.MessageReceivedCallback
                        public void onMessageReceived(CastDevice castDevice, String namespace, String message) {
                            zzjs.this.zzbB(message);
                        }
                    });
                    zzjs.this.zzly();
                    zzjs.this.zzlx();
                    zzjs.this.zza((String) null, 1100, (JSONObject) null, zzlA());
                } catch (IOException | IllegalStateException e) {
                    zzlA().zza(-1L, 8, null);
                }
            }
        });
    }

    public synchronized PendingResult<GameManagerClient.GameManagerResult> zza(final String str, final int i, final JSONObject jSONObject) throws IllegalStateException {
        zzlv();
        return this.zzTr.zzb(new zza() { // from class: com.google.android.gms.internal.zzjs.2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super();
            }

            @Override // com.google.android.gms.internal.zzjs.zzb
            public void execute() {
                int zzaJ = zzjv.zzaJ(i);
                if (zzaJ != 0) {
                    zzjs.this.zza(str, zzaJ, jSONObject, zzlA());
                    return;
                }
                zzlA().zza(-1L, 2001, null);
                zzjs.zzQW.zzf("sendPlayerRequest for unsupported playerState: %d", Integer.valueOf(i));
            }
        });
    }

    @Override // com.google.android.gms.cast.internal.zzd
    public void zzb(long j, int i) {
        zzb(j, i, null);
    }

    public synchronized String zzbA(String str) throws IllegalStateException {
        return str == null ? null : this.zzTn.get(str);
    }

    @Override // com.google.android.gms.cast.internal.zzd
    public final void zzbB(String str) {
        zzQW.zzb("message received: %s", str);
        try {
            zzju zzh = zzju.zzh(new JSONObject(str));
            if (zzh == null) {
                zzQW.zzf("Could not parse game manager message from string: %s", str);
            } else if ((isInitialized() || zzh.zzlH() != null) && !isDisposed()) {
                boolean z = zzh.zzlC() == 1;
                if (z && !TextUtils.isEmpty(zzh.zzlG())) {
                    this.zzTn.put(zzh.getPlayerId(), zzh.zzlG());
                    zzlx();
                }
                if (zzh.getStatusCode() == 0) {
                    zza(zzh);
                } else {
                    zzQW.zzf("Not updating from game message because the message contains error code: %d", Integer.valueOf(zzh.getStatusCode()));
                }
                int zzaI = zzaI(zzh.getStatusCode());
                if (z) {
                    zzb(zzh.getRequestId(), zzaI, zzh);
                }
                if (isInitialized() && zzaI == 0) {
                    zzlw();
                }
            }
        } catch (JSONException e) {
            zzQW.zzf("Message is malformed (%s); ignoring: %s", e.getMessage(), str);
        }
    }

    @Override // com.google.android.gms.cast.internal.zzc
    protected boolean zzz(long j) {
        boolean z;
        Iterator<com.google.android.gms.cast.internal.zzp> it = this.zzTo.iterator();
        while (it.hasNext()) {
            if (it.next().zzd(j, 15)) {
                it.remove();
            }
        }
        synchronized (com.google.android.gms.cast.internal.zzp.zzVr) {
            Iterator<com.google.android.gms.cast.internal.zzp> it2 = this.zzTo.iterator();
            while (true) {
                if (!it2.hasNext()) {
                    z = false;
                    break;
                } else if (it2.next().zzme()) {
                    z = true;
                    break;
                }
            }
        }
        return z;
    }
}
