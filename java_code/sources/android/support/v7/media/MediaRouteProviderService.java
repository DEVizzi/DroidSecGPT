package android.support.v7.media;

import android.app.Service;
import android.content.Intent;
import android.os.Bundle;
import android.os.DeadObjectException;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.support.v7.media.MediaRouteProvider;
import android.support.v7.media.MediaRouteSelector;
import android.support.v7.media.MediaRouter;
import android.util.Log;
import android.util.SparseArray;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
/* loaded from: classes.dex */
public abstract class MediaRouteProviderService extends Service {
    private static final int PRIVATE_MSG_CLIENT_DIED = 1;
    public static final String SERVICE_INTERFACE = "android.media.MediaRouteProviderService";
    private MediaRouteDiscoveryRequest mCompositeDiscoveryRequest;
    private MediaRouteProvider mProvider;
    private static final String TAG = "MediaRouteProviderSrv";
    private static final boolean DEBUG = Log.isLoggable(TAG, 3);
    private final ArrayList<ClientRecord> mClients = new ArrayList<>();
    private final ReceiveHandler mReceiveHandler = new ReceiveHandler(this);
    private final Messenger mReceiveMessenger = new Messenger(this.mReceiveHandler);
    private final PrivateHandler mPrivateHandler = new PrivateHandler();
    private final ProviderCallback mProviderCallback = new ProviderCallback();

    public abstract MediaRouteProvider onCreateMediaRouteProvider();

    public MediaRouteProvider getMediaRouteProvider() {
        return this.mProvider;
    }

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        MediaRouteProvider provider;
        if (intent.getAction().equals("android.media.MediaRouteProviderService")) {
            if (this.mProvider == null && (provider = onCreateMediaRouteProvider()) != null) {
                String providerPackage = provider.getMetadata().getPackageName();
                if (!providerPackage.equals(getPackageName())) {
                    throw new IllegalStateException("onCreateMediaRouteProvider() returned a provider whose package name does not match the package name of the service.  A media route provider service can only export its own media route providers.  Provider package name: " + providerPackage + ".  Service package name: " + getPackageName() + ".");
                }
                this.mProvider = provider;
                this.mProvider.setCallback(this.mProviderCallback);
            }
            if (this.mProvider != null) {
                return this.mReceiveMessenger.getBinder();
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean onRegisterClient(Messenger messenger, int requestId, int version) {
        if (version >= 1) {
            int index = findClient(messenger);
            if (index < 0) {
                ClientRecord client = new ClientRecord(messenger, version);
                if (client.register()) {
                    this.mClients.add(client);
                    if (DEBUG) {
                        Log.d(TAG, client + ": Registered, version=" + version);
                    }
                    if (requestId != 0) {
                        MediaRouteProviderDescriptor descriptor = this.mProvider.getDescriptor();
                        sendReply(messenger, 2, requestId, 1, descriptor != null ? descriptor.asBundle() : null, null);
                        return true;
                    }
                    return true;
                }
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean onUnregisterClient(Messenger messenger, int requestId) {
        int index = findClient(messenger);
        if (index >= 0) {
            ClientRecord client = this.mClients.remove(index);
            if (DEBUG) {
                Log.d(TAG, client + ": Unregistered");
            }
            client.dispose();
            sendGenericSuccess(messenger, requestId);
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onBinderDied(Messenger messenger) {
        int index = findClient(messenger);
        if (index >= 0) {
            ClientRecord client = this.mClients.remove(index);
            if (DEBUG) {
                Log.d(TAG, client + ": Binder died");
            }
            client.dispose();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean onCreateRouteController(Messenger messenger, int requestId, int controllerId, String routeId) {
        ClientRecord client = getClient(messenger);
        if (client == null || !client.createRouteController(routeId, controllerId)) {
            return false;
        }
        if (DEBUG) {
            Log.d(TAG, client + ": Route controller created, controllerId=" + controllerId + ", routeId=" + routeId);
        }
        sendGenericSuccess(messenger, requestId);
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean onReleaseRouteController(Messenger messenger, int requestId, int controllerId) {
        ClientRecord client = getClient(messenger);
        if (client == null || !client.releaseRouteController(controllerId)) {
            return false;
        }
        if (DEBUG) {
            Log.d(TAG, client + ": Route controller released, controllerId=" + controllerId);
        }
        sendGenericSuccess(messenger, requestId);
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean onSelectRoute(Messenger messenger, int requestId, int controllerId) {
        MediaRouteProvider.RouteController controller;
        ClientRecord client = getClient(messenger);
        if (client == null || (controller = client.getRouteController(controllerId)) == null) {
            return false;
        }
        controller.onSelect();
        if (DEBUG) {
            Log.d(TAG, client + ": Route selected, controllerId=" + controllerId);
        }
        sendGenericSuccess(messenger, requestId);
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean onUnselectRoute(Messenger messenger, int requestId, int controllerId, int reason) {
        MediaRouteProvider.RouteController controller;
        ClientRecord client = getClient(messenger);
        if (client == null || (controller = client.getRouteController(controllerId)) == null) {
            return false;
        }
        controller.onUnselect(reason);
        if (DEBUG) {
            Log.d(TAG, client + ": Route unselected, controllerId=" + controllerId);
        }
        sendGenericSuccess(messenger, requestId);
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean onSetRouteVolume(Messenger messenger, int requestId, int controllerId, int volume) {
        MediaRouteProvider.RouteController controller;
        ClientRecord client = getClient(messenger);
        if (client == null || (controller = client.getRouteController(controllerId)) == null) {
            return false;
        }
        controller.onSetVolume(volume);
        if (DEBUG) {
            Log.d(TAG, client + ": Route volume changed, controllerId=" + controllerId + ", volume=" + volume);
        }
        sendGenericSuccess(messenger, requestId);
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean onUpdateRouteVolume(Messenger messenger, int requestId, int controllerId, int delta) {
        MediaRouteProvider.RouteController controller;
        ClientRecord client = getClient(messenger);
        if (client == null || (controller = client.getRouteController(controllerId)) == null) {
            return false;
        }
        controller.onUpdateVolume(delta);
        if (DEBUG) {
            Log.d(TAG, client + ": Route volume updated, controllerId=" + controllerId + ", delta=" + delta);
        }
        sendGenericSuccess(messenger, requestId);
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean onRouteControlRequest(final Messenger messenger, final int requestId, final int controllerId, final Intent intent) {
        MediaRouteProvider.RouteController controller;
        final ClientRecord client = getClient(messenger);
        if (client != null && (controller = client.getRouteController(controllerId)) != null) {
            MediaRouter.ControlRequestCallback callback = null;
            if (requestId != 0) {
                callback = new MediaRouter.ControlRequestCallback() { // from class: android.support.v7.media.MediaRouteProviderService.1
                    @Override // android.support.v7.media.MediaRouter.ControlRequestCallback
                    public void onResult(Bundle data) {
                        if (MediaRouteProviderService.DEBUG) {
                            Log.d(MediaRouteProviderService.TAG, client + ": Route control request succeeded, controllerId=" + controllerId + ", intent=" + intent + ", data=" + data);
                        }
                        if (MediaRouteProviderService.this.findClient(messenger) >= 0) {
                            MediaRouteProviderService.sendReply(messenger, 3, requestId, 0, data, null);
                        }
                    }

                    @Override // android.support.v7.media.MediaRouter.ControlRequestCallback
                    public void onError(String error, Bundle data) {
                        if (MediaRouteProviderService.DEBUG) {
                            Log.d(MediaRouteProviderService.TAG, client + ": Route control request failed, controllerId=" + controllerId + ", intent=" + intent + ", error=" + error + ", data=" + data);
                        }
                        if (MediaRouteProviderService.this.findClient(messenger) >= 0) {
                            if (error == null) {
                                MediaRouteProviderService.sendReply(messenger, 4, requestId, 0, data, null);
                                return;
                            }
                            Bundle bundle = new Bundle();
                            bundle.putString(MediaRouteProviderProtocol.SERVICE_DATA_ERROR, error);
                            MediaRouteProviderService.sendReply(messenger, 4, requestId, 0, data, bundle);
                        }
                    }
                };
            }
            if (controller.onControlRequest(intent, callback)) {
                if (DEBUG) {
                    Log.d(TAG, client + ": Route control request delivered, controllerId=" + controllerId + ", intent=" + intent);
                }
                return true;
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean onSetDiscoveryRequest(Messenger messenger, int requestId, MediaRouteDiscoveryRequest request) {
        ClientRecord client = getClient(messenger);
        if (client != null) {
            boolean actuallyChanged = client.setDiscoveryRequest(request);
            if (DEBUG) {
                Log.d(TAG, client + ": Set discovery request, request=" + request + ", actuallyChanged=" + actuallyChanged + ", compositeDiscoveryRequest=" + this.mCompositeDiscoveryRequest);
            }
            sendGenericSuccess(messenger, requestId);
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendDescriptorChanged(MediaRouteProviderDescriptor descriptor) {
        Bundle descriptorBundle = descriptor != null ? descriptor.asBundle() : null;
        int count = this.mClients.size();
        for (int i = 0; i < count; i++) {
            ClientRecord client = this.mClients.get(i);
            sendReply(client.mMessenger, 5, 0, 0, descriptorBundle, null);
            if (DEBUG) {
                Log.d(TAG, client + ": Sent descriptor change event, descriptor=" + descriptor);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean updateCompositeDiscoveryRequest() {
        MediaRouteDiscoveryRequest composite = null;
        MediaRouteSelector.Builder selectorBuilder = null;
        boolean activeScan = false;
        int count = this.mClients.size();
        for (int i = 0; i < count; i++) {
            MediaRouteDiscoveryRequest request = this.mClients.get(i).mDiscoveryRequest;
            if (request != null && (!request.getSelector().isEmpty() || request.isActiveScan())) {
                activeScan |= request.isActiveScan();
                if (composite == null) {
                    composite = request;
                } else {
                    if (selectorBuilder == null) {
                        selectorBuilder = new MediaRouteSelector.Builder(composite.getSelector());
                    }
                    selectorBuilder.addSelector(request.getSelector());
                }
            }
        }
        if (selectorBuilder != null) {
            composite = new MediaRouteDiscoveryRequest(selectorBuilder.build(), activeScan);
        }
        if (this.mCompositeDiscoveryRequest == composite || (this.mCompositeDiscoveryRequest != null && this.mCompositeDiscoveryRequest.equals(composite))) {
            return false;
        }
        this.mCompositeDiscoveryRequest = composite;
        this.mProvider.setDiscoveryRequest(composite);
        return true;
    }

    private ClientRecord getClient(Messenger messenger) {
        int index = findClient(messenger);
        if (index >= 0) {
            return this.mClients.get(index);
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int findClient(Messenger messenger) {
        int count = this.mClients.size();
        for (int i = 0; i < count; i++) {
            ClientRecord client = this.mClients.get(i);
            if (client.hasMessenger(messenger)) {
                return i;
            }
        }
        return -1;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void sendGenericFailure(Messenger messenger, int requestId) {
        if (requestId != 0) {
            sendReply(messenger, 0, requestId, 0, null, null);
        }
    }

    private static void sendGenericSuccess(Messenger messenger, int requestId) {
        if (requestId != 0) {
            sendReply(messenger, 1, requestId, 0, null, null);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void sendReply(Messenger messenger, int what, int requestId, int arg, Object obj, Bundle data) {
        Message msg = Message.obtain();
        msg.what = what;
        msg.arg1 = requestId;
        msg.arg2 = arg;
        msg.obj = obj;
        msg.setData(data);
        try {
            messenger.send(msg);
        } catch (DeadObjectException e) {
        } catch (RemoteException ex) {
            Log.e(TAG, "Could not send message to " + getClientId(messenger), ex);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static String getClientId(Messenger messenger) {
        return "Client connection " + messenger.getBinder().toString();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public final class PrivateHandler extends Handler {
        private PrivateHandler() {
        }

        @Override // android.os.Handler
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case 1:
                    MediaRouteProviderService.this.onBinderDied((Messenger) msg.obj);
                    return;
                default:
                    return;
            }
        }
    }

    /* loaded from: classes.dex */
    private final class ProviderCallback extends MediaRouteProvider.Callback {
        private ProviderCallback() {
        }

        @Override // android.support.v7.media.MediaRouteProvider.Callback
        public void onDescriptorChanged(MediaRouteProvider provider, MediaRouteProviderDescriptor descriptor) {
            MediaRouteProviderService.this.sendDescriptorChanged(descriptor);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public final class ClientRecord implements IBinder.DeathRecipient {
        private final SparseArray<MediaRouteProvider.RouteController> mControllers = new SparseArray<>();
        public MediaRouteDiscoveryRequest mDiscoveryRequest;
        public final Messenger mMessenger;
        public final int mVersion;

        public ClientRecord(Messenger messenger, int version) {
            this.mMessenger = messenger;
            this.mVersion = version;
        }

        public boolean register() {
            try {
                this.mMessenger.getBinder().linkToDeath(this, 0);
                return true;
            } catch (RemoteException e) {
                binderDied();
                return false;
            }
        }

        public void dispose() {
            int count = this.mControllers.size();
            for (int i = 0; i < count; i++) {
                this.mControllers.valueAt(i).onRelease();
            }
            this.mControllers.clear();
            this.mMessenger.getBinder().unlinkToDeath(this, 0);
            setDiscoveryRequest(null);
        }

        public boolean hasMessenger(Messenger other) {
            return this.mMessenger.getBinder() == other.getBinder();
        }

        public boolean createRouteController(String routeId, int controllerId) {
            MediaRouteProvider.RouteController controller;
            if (this.mControllers.indexOfKey(controllerId) >= 0 || (controller = MediaRouteProviderService.this.mProvider.onCreateRouteController(routeId)) == null) {
                return false;
            }
            this.mControllers.put(controllerId, controller);
            return true;
        }

        public boolean releaseRouteController(int controllerId) {
            MediaRouteProvider.RouteController controller = this.mControllers.get(controllerId);
            if (controller != null) {
                this.mControllers.remove(controllerId);
                controller.onRelease();
                return true;
            }
            return false;
        }

        public MediaRouteProvider.RouteController getRouteController(int controllerId) {
            return this.mControllers.get(controllerId);
        }

        public boolean setDiscoveryRequest(MediaRouteDiscoveryRequest request) {
            if (this.mDiscoveryRequest == request || (this.mDiscoveryRequest != null && this.mDiscoveryRequest.equals(request))) {
                return false;
            }
            this.mDiscoveryRequest = request;
            return MediaRouteProviderService.this.updateCompositeDiscoveryRequest();
        }

        @Override // android.os.IBinder.DeathRecipient
        public void binderDied() {
            MediaRouteProviderService.this.mPrivateHandler.obtainMessage(1, this.mMessenger).sendToTarget();
        }

        public String toString() {
            return MediaRouteProviderService.getClientId(this.mMessenger);
        }
    }

    /* loaded from: classes.dex */
    private static final class ReceiveHandler extends Handler {
        private final WeakReference<MediaRouteProviderService> mServiceRef;

        public ReceiveHandler(MediaRouteProviderService service) {
            this.mServiceRef = new WeakReference<>(service);
        }

        @Override // android.os.Handler
        public void handleMessage(Message msg) {
            Messenger messenger = msg.replyTo;
            if (!MediaRouteProviderProtocol.isValidRemoteMessenger(messenger)) {
                if (MediaRouteProviderService.DEBUG) {
                    Log.d(MediaRouteProviderService.TAG, "Ignoring message without valid reply messenger.");
                    return;
                }
                return;
            }
            int what = msg.what;
            int requestId = msg.arg1;
            int arg = msg.arg2;
            Object obj = msg.obj;
            Bundle data = msg.peekData();
            if (!processMessage(what, messenger, requestId, arg, obj, data)) {
                if (MediaRouteProviderService.DEBUG) {
                    Log.d(MediaRouteProviderService.TAG, MediaRouteProviderService.getClientId(messenger) + ": Message failed, what=" + what + ", requestId=" + requestId + ", arg=" + arg + ", obj=" + obj + ", data=" + data);
                }
                MediaRouteProviderService.sendGenericFailure(messenger, requestId);
            }
        }

        private boolean processMessage(int what, Messenger messenger, int requestId, int arg, Object obj, Bundle data) {
            MediaRouteProviderService service = this.mServiceRef.get();
            if (service != null) {
                switch (what) {
                    case 1:
                        return service.onRegisterClient(messenger, requestId, arg);
                    case 2:
                        return service.onUnregisterClient(messenger, requestId);
                    case 3:
                        String routeId = data.getString(MediaRouteProviderProtocol.CLIENT_DATA_ROUTE_ID);
                        if (routeId != null) {
                            return service.onCreateRouteController(messenger, requestId, arg, routeId);
                        }
                        return false;
                    case 4:
                        return service.onReleaseRouteController(messenger, requestId, arg);
                    case 5:
                        return service.onSelectRoute(messenger, requestId, arg);
                    case 6:
                        int reason = data != null ? data.getInt(MediaRouteProviderProtocol.CLIENT_DATA_UNSELECT_REASON, 0) : 0;
                        return service.onUnselectRoute(messenger, requestId, arg, reason);
                    case 7:
                        int volume = data.getInt(MediaRouteProviderProtocol.CLIENT_DATA_VOLUME, -1);
                        if (volume >= 0) {
                            return service.onSetRouteVolume(messenger, requestId, arg, volume);
                        }
                        return false;
                    case 8:
                        int delta = data.getInt(MediaRouteProviderProtocol.CLIENT_DATA_VOLUME, 0);
                        if (delta != 0) {
                            return service.onUpdateRouteVolume(messenger, requestId, arg, delta);
                        }
                        return false;
                    case 9:
                        if (obj instanceof Intent) {
                            return service.onRouteControlRequest(messenger, requestId, arg, (Intent) obj);
                        }
                        return false;
                    case 10:
                        if (obj == null || (obj instanceof Bundle)) {
                            MediaRouteDiscoveryRequest request = MediaRouteDiscoveryRequest.fromBundle((Bundle) obj);
                            request = (request == null || !request.isValid()) ? null : null;
                            return service.onSetDiscoveryRequest(messenger, requestId, request);
                        }
                        return false;
                    default:
                        return false;
                }
            }
            return false;
        }
    }
}
