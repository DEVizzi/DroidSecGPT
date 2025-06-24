package com.google.android.gms.wearable.internal;

import android.os.ParcelFileDescriptor;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.wearable.CapabilityApi;
import com.google.android.gms.wearable.CapabilityInfo;
import com.google.android.gms.wearable.Channel;
import com.google.android.gms.wearable.ChannelApi;
import com.google.android.gms.wearable.DataApi;
import com.google.android.gms.wearable.DataItemBuffer;
import com.google.android.gms.wearable.MessageApi;
import com.google.android.gms.wearable.NodeApi;
import com.google.android.gms.wearable.internal.ChannelImpl;
import com.google.android.gms.wearable.internal.zzav;
import com.google.android.gms.wearable.internal.zzax;
import com.google.android.gms.wearable.internal.zzg;
import com.google.android.gms.wearable.internal.zzi;
import com.google.android.gms.wearable.internal.zzu;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.FutureTask;
/* loaded from: classes.dex */
final class zzbj {

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zza extends zzb<CapabilityApi.AddLocalCapabilityResult> {
        public zza(zza.zzb<CapabilityApi.AddLocalCapabilityResult> zzbVar) {
            super(zzbVar);
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zza(AddLocalCapabilityResponse addLocalCapabilityResponse) {
            zzP(new zzg.zzb(zzbg.zzfn(addLocalCapabilityResponse.statusCode)));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static abstract class zzb<T> extends com.google.android.gms.wearable.internal.zza {
        private zza.zzb<T> zzNO;

        public zzb(zza.zzb<T> zzbVar) {
            this.zzNO = zzbVar;
        }

        public void zzP(T t) {
            zza.zzb<T> zzbVar = this.zzNO;
            if (zzbVar != null) {
                zzbVar.zzm(t);
                this.zzNO = null;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzc extends zzb<Status> {
        public zzc(zza.zzb<Status> zzbVar) {
            super(zzbVar);
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zza(CloseChannelResponse closeChannelResponse) {
            zzP(new Status(closeChannelResponse.statusCode));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzd extends zzb<Status> {
        public zzd(zza.zzb<Status> zzbVar) {
            super(zzbVar);
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zzb(CloseChannelResponse closeChannelResponse) {
            zzP(new Status(closeChannelResponse.statusCode));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zze extends zzb<DataApi.DeleteDataItemsResult> {
        public zze(zza.zzb<DataApi.DeleteDataItemsResult> zzbVar) {
            super(zzbVar);
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zza(DeleteDataItemsResponse deleteDataItemsResponse) {
            zzP(new zzu.zzc(zzbg.zzfn(deleteDataItemsResponse.statusCode), deleteDataItemsResponse.zzaUp));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzf extends zzb<CapabilityApi.GetAllCapabilitiesResult> {
        public zzf(zza.zzb<CapabilityApi.GetAllCapabilitiesResult> zzbVar) {
            super(zzbVar);
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zza(GetAllCapabilitiesResponse getAllCapabilitiesResponse) {
            zzP(new zzg.zzd(zzbg.zzfn(getAllCapabilitiesResponse.statusCode), zzbj.zzv(getAllCapabilitiesResponse.zzaUq)));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzg extends zzb<CapabilityApi.GetCapabilityResult> {
        public zzg(zza.zzb<CapabilityApi.GetCapabilityResult> zzbVar) {
            super(zzbVar);
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zza(GetCapabilityResponse getCapabilityResponse) {
            zzP(new zzg.zze(zzbg.zzfn(getCapabilityResponse.statusCode), new zzg.zzc(getCapabilityResponse.zzaUr)));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzh extends zzb<Channel.GetInputStreamResult> {
        private final com.google.android.gms.wearable.internal.zzq zzaUQ;

        public zzh(zza.zzb<Channel.GetInputStreamResult> zzbVar, com.google.android.gms.wearable.internal.zzq zzqVar) {
            super(zzbVar);
            this.zzaUQ = (com.google.android.gms.wearable.internal.zzq) com.google.android.gms.common.internal.zzu.zzu(zzqVar);
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zza(GetChannelInputStreamResponse getChannelInputStreamResponse) {
            com.google.android.gms.wearable.internal.zzm zzmVar = null;
            if (getChannelInputStreamResponse.zzaUs != null) {
                zzmVar = new com.google.android.gms.wearable.internal.zzm(new ParcelFileDescriptor.AutoCloseInputStream(getChannelInputStreamResponse.zzaUs));
                this.zzaUQ.zza(zzmVar.zzBb());
            }
            zzP(new ChannelImpl.zza(new Status(getChannelInputStreamResponse.statusCode), zzmVar));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzi extends zzb<Channel.GetOutputStreamResult> {
        private final com.google.android.gms.wearable.internal.zzq zzaUQ;

        public zzi(zza.zzb<Channel.GetOutputStreamResult> zzbVar, com.google.android.gms.wearable.internal.zzq zzqVar) {
            super(zzbVar);
            this.zzaUQ = (com.google.android.gms.wearable.internal.zzq) com.google.android.gms.common.internal.zzu.zzu(zzqVar);
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zza(GetChannelOutputStreamResponse getChannelOutputStreamResponse) {
            com.google.android.gms.wearable.internal.zzn zznVar = null;
            if (getChannelOutputStreamResponse.zzaUs != null) {
                zznVar = new com.google.android.gms.wearable.internal.zzn(new ParcelFileDescriptor.AutoCloseOutputStream(getChannelOutputStreamResponse.zzaUs));
                this.zzaUQ.zza(zznVar.zzBb());
            }
            zzP(new ChannelImpl.zzb(new Status(getChannelOutputStreamResponse.statusCode), zznVar));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzj extends zzb<NodeApi.GetConnectedNodesResult> {
        public zzj(zza.zzb<NodeApi.GetConnectedNodesResult> zzbVar) {
            super(zzbVar);
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zza(GetConnectedNodesResponse getConnectedNodesResponse) {
            ArrayList arrayList = new ArrayList();
            arrayList.addAll(getConnectedNodesResponse.zzaUw);
            zzP(new zzax.zzb(zzbg.zzfn(getConnectedNodesResponse.statusCode), arrayList));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzk extends zzb<DataApi.DataItemResult> {
        public zzk(zza.zzb<DataApi.DataItemResult> zzbVar) {
            super(zzbVar);
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zza(GetDataItemResponse getDataItemResponse) {
            zzP(new zzu.zzb(zzbg.zzfn(getDataItemResponse.statusCode), getDataItemResponse.zzaUx));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzl extends zzb<DataItemBuffer> {
        public zzl(zza.zzb<DataItemBuffer> zzbVar) {
            super(zzbVar);
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zzad(DataHolder dataHolder) {
            zzP(new DataItemBuffer(dataHolder));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzm extends zzb<DataApi.GetFdForAssetResult> {
        public zzm(zza.zzb<DataApi.GetFdForAssetResult> zzbVar) {
            super(zzbVar);
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zza(GetFdForAssetResponse getFdForAssetResponse) {
            zzP(new zzu.zzd(zzbg.zzfn(getFdForAssetResponse.statusCode), getFdForAssetResponse.zzaUy));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzn extends zzb<NodeApi.GetLocalNodeResult> {
        public zzn(zza.zzb<NodeApi.GetLocalNodeResult> zzbVar) {
            super(zzbVar);
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zza(GetLocalNodeResponse getLocalNodeResponse) {
            zzP(new zzax.zzc(zzbg.zzfn(getLocalNodeResponse.statusCode), getLocalNodeResponse.zzaUz));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzo extends com.google.android.gms.wearable.internal.zza {
        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zza(Status status) {
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzp extends zzb<ChannelApi.OpenChannelResult> {
        public zzp(zza.zzb<ChannelApi.OpenChannelResult> zzbVar) {
            super(zzbVar);
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zza(OpenChannelResponse openChannelResponse) {
            zzP(new zzi.zzb(zzbg.zzfn(openChannelResponse.statusCode), openChannelResponse.zzaTP));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzq extends zzb<DataApi.DataItemResult> {
        private final List<FutureTask<Boolean>> zzwE;

        /* JADX INFO: Access modifiers changed from: package-private */
        public zzq(zza.zzb<DataApi.DataItemResult> zzbVar, List<FutureTask<Boolean>> list) {
            super(zzbVar);
            this.zzwE = list;
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zza(PutDataResponse putDataResponse) {
            zzP(new zzu.zzb(zzbg.zzfn(putDataResponse.statusCode), putDataResponse.zzaUx));
            if (putDataResponse.statusCode != 0) {
                for (FutureTask<Boolean> futureTask : this.zzwE) {
                    futureTask.cancel(true);
                }
            }
        }
    }

    /* loaded from: classes.dex */
    static final class zzr extends zzb<Status> {
        public zzr(zza.zzb<Status> zzbVar) {
            super(zzbVar);
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zza(ChannelSendFileResponse channelSendFileResponse) {
            zzP(new Status(channelSendFileResponse.statusCode));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzs extends zzb<CapabilityApi.RemoveLocalCapabilityResult> {
        public zzs(zza.zzb<CapabilityApi.RemoveLocalCapabilityResult> zzbVar) {
            super(zzbVar);
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zza(RemoveLocalCapabilityResponse removeLocalCapabilityResponse) {
            zzP(new zzg.zzb(zzbg.zzfn(removeLocalCapabilityResponse.statusCode)));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzt extends zzb<MessageApi.SendMessageResult> {
        public zzt(zza.zzb<MessageApi.SendMessageResult> zzbVar) {
            super(zzbVar);
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zza(SendMessageResponse sendMessageResponse) {
            zzP(new zzav.zzb(zzbg.zzfn(sendMessageResponse.statusCode), sendMessageResponse.zzaxg));
        }
    }

    /* loaded from: classes.dex */
    static final class zzu extends zzb<Status> {
        public zzu(zza.zzb<Status> zzbVar) {
            super(zzbVar);
        }

        @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzar
        public void zza(ChannelReceiveFileResponse channelReceiveFileResponse) {
            zzP(new Status(channelReceiveFileResponse.statusCode));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static Map<String, CapabilityInfo> zzv(List<CapabilityInfoParcelable> list) {
        HashMap hashMap = new HashMap(list.size() * 2);
        for (CapabilityInfoParcelable capabilityInfoParcelable : list) {
            hashMap.put(capabilityInfoParcelable.getName(), new zzg.zzc(capabilityInfoParcelable));
        }
        return hashMap;
    }
}
