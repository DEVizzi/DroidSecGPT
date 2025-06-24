package com.google.android.gms.wearable.internal;

import android.net.Uri;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.wearable.Channel;
import com.google.android.gms.wearable.ChannelApi;
import com.google.android.gms.wearable.internal.zzi;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
/* loaded from: classes.dex */
public class ChannelImpl implements SafeParcelable, Channel {
    public static final Parcelable.Creator<ChannelImpl> CREATOR = new zzl();
    final int zzCY;
    private final String zzaST;
    private final String zzaTK;
    private final String zzaTQ;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zza implements Channel.GetInputStreamResult {
        private final Status zzOt;
        private final InputStream zzaTV;

        /* JADX INFO: Access modifiers changed from: package-private */
        public zza(Status status, InputStream inputStream) {
            this.zzOt = (Status) com.google.android.gms.common.internal.zzu.zzu(status);
            this.zzaTV = inputStream;
        }

        @Override // com.google.android.gms.wearable.Channel.GetInputStreamResult
        public InputStream getInputStream() {
            return this.zzaTV;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }

        @Override // com.google.android.gms.common.api.Releasable
        public void release() {
            if (this.zzaTV != null) {
                try {
                    this.zzaTV.close();
                } catch (IOException e) {
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzb implements Channel.GetOutputStreamResult {
        private final Status zzOt;
        private final OutputStream zzaTW;

        /* JADX INFO: Access modifiers changed from: package-private */
        public zzb(Status status, OutputStream outputStream) {
            this.zzOt = (Status) com.google.android.gms.common.internal.zzu.zzu(status);
            this.zzaTW = outputStream;
        }

        @Override // com.google.android.gms.wearable.Channel.GetOutputStreamResult
        public OutputStream getOutputStream() {
            return this.zzaTW;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }

        @Override // com.google.android.gms.common.api.Releasable
        public void release() {
            if (this.zzaTW != null) {
                try {
                    this.zzaTW.close();
                } catch (IOException e) {
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ChannelImpl(int versionCode, String token, String nodeId, String path) {
        this.zzCY = versionCode;
        this.zzaTK = (String) com.google.android.gms.common.internal.zzu.zzu(token);
        this.zzaST = (String) com.google.android.gms.common.internal.zzu.zzu(nodeId);
        this.zzaTQ = (String) com.google.android.gms.common.internal.zzu.zzu(path);
    }

    @Override // com.google.android.gms.wearable.Channel
    public PendingResult<Status> addListener(GoogleApiClient client, ChannelApi.ChannelListener listener) {
        com.google.android.gms.common.internal.zzu.zzb(client, "client is null");
        com.google.android.gms.common.internal.zzu.zzb(listener, "listener is null");
        return client.zza((GoogleApiClient) new zzi.zza(client, listener, this.zzaTK));
    }

    @Override // com.google.android.gms.wearable.Channel
    public PendingResult<Status> close(GoogleApiClient client) {
        return client.zzb(new zzf<Status>(client) { // from class: com.google.android.gms.wearable.internal.ChannelImpl.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zzt(this, ChannelImpl.this.zzaTK);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzb */
            public Status createFailedResult(Status status) {
                return status;
            }
        });
    }

    @Override // com.google.android.gms.wearable.Channel
    public PendingResult<Status> close(GoogleApiClient client, final int errorCode) {
        return client.zzb(new zzf<Status>(client) { // from class: com.google.android.gms.wearable.internal.ChannelImpl.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zzh(this, ChannelImpl.this.zzaTK, errorCode);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzb */
            public Status createFailedResult(Status status) {
                return status;
            }
        });
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (other instanceof ChannelImpl) {
            ChannelImpl channelImpl = (ChannelImpl) other;
            return this.zzaTK.equals(channelImpl.zzaTK) && com.google.android.gms.common.internal.zzt.equal(channelImpl.zzaST, this.zzaST) && com.google.android.gms.common.internal.zzt.equal(channelImpl.zzaTQ, this.zzaTQ) && channelImpl.zzCY == this.zzCY;
        }
        return false;
    }

    @Override // com.google.android.gms.wearable.Channel
    public PendingResult<Channel.GetInputStreamResult> getInputStream(GoogleApiClient client) {
        return client.zzb(new zzf<Channel.GetInputStreamResult>(client) { // from class: com.google.android.gms.wearable.internal.ChannelImpl.3
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zzu(this, ChannelImpl.this.zzaTK);
            }

            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzbb */
            public Channel.GetInputStreamResult createFailedResult(Status status) {
                return new zza(status, null);
            }
        });
    }

    @Override // com.google.android.gms.wearable.Channel
    public String getNodeId() {
        return this.zzaST;
    }

    @Override // com.google.android.gms.wearable.Channel
    public PendingResult<Channel.GetOutputStreamResult> getOutputStream(GoogleApiClient client) {
        return client.zzb(new zzf<Channel.GetOutputStreamResult>(client) { // from class: com.google.android.gms.wearable.internal.ChannelImpl.4
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zzv(this, ChannelImpl.this.zzaTK);
            }

            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzbc */
            public Channel.GetOutputStreamResult createFailedResult(Status status) {
                return new zzb(status, null);
            }
        });
    }

    @Override // com.google.android.gms.wearable.Channel
    public String getPath() {
        return this.zzaTQ;
    }

    public String getToken() {
        return this.zzaTK;
    }

    public int hashCode() {
        return this.zzaTK.hashCode();
    }

    @Override // com.google.android.gms.wearable.Channel
    public PendingResult<Status> receiveFile(GoogleApiClient client, final Uri uri, final boolean append) {
        com.google.android.gms.common.internal.zzu.zzb(client, "client is null");
        com.google.android.gms.common.internal.zzu.zzb(uri, "uri is null");
        return client.zzb(new zzf<Status>(client) { // from class: com.google.android.gms.wearable.internal.ChannelImpl.5
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zza(this, ChannelImpl.this.zzaTK, uri, append);
            }

            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzb */
            public Status createFailedResult(Status status) {
                return status;
            }
        });
    }

    @Override // com.google.android.gms.wearable.Channel
    public PendingResult<Status> removeListener(GoogleApiClient client, ChannelApi.ChannelListener listener) {
        com.google.android.gms.common.internal.zzu.zzb(client, "client is null");
        com.google.android.gms.common.internal.zzu.zzb(listener, "listener is null");
        return client.zza((GoogleApiClient) new zzi.zzc(client, listener, this.zzaTK));
    }

    @Override // com.google.android.gms.wearable.Channel
    public PendingResult<Status> sendFile(GoogleApiClient client, Uri uri) {
        return sendFile(client, uri, 0L, -1L);
    }

    @Override // com.google.android.gms.wearable.Channel
    public PendingResult<Status> sendFile(GoogleApiClient client, final Uri uri, final long startOffset, final long length) {
        com.google.android.gms.common.internal.zzu.zzb(client, "client is null");
        com.google.android.gms.common.internal.zzu.zzb(this.zzaTK, "token is null");
        com.google.android.gms.common.internal.zzu.zzb(uri, "uri is null");
        com.google.android.gms.common.internal.zzu.zzb(startOffset >= 0, "startOffset is negative: %s", Long.valueOf(startOffset));
        com.google.android.gms.common.internal.zzu.zzb(length >= 0 || length == -1, "invalid length: %s", Long.valueOf(length));
        return client.zzb(new zzf<Status>(client) { // from class: com.google.android.gms.wearable.internal.ChannelImpl.6
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zza(this, ChannelImpl.this.zzaTK, uri, startOffset, length);
            }

            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzb */
            public Status createFailedResult(Status status) {
                return status;
            }
        });
    }

    public String toString() {
        return "ChannelImpl{versionCode=" + this.zzCY + ", token='" + this.zzaTK + "', nodeId='" + this.zzaST + "', path='" + this.zzaTQ + "'}";
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzl.zza(this, dest, flags);
    }
}
