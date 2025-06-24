package com.google.android.gms.nearby.messages;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
/* loaded from: classes.dex */
public class Message implements SafeParcelable {
    public static final Parcelable.Creator<Message> CREATOR = new zza();
    private final byte[] content;
    private final String type;
    final int versionCode;
    private final String zzaby;

    /* JADX INFO: Access modifiers changed from: package-private */
    public Message(int versionCode, byte[] content, String namespace, String type) {
        zzu.zzb(content.length <= 102400, "Content length(%d) must not exceed MAX_CONTENT_SIZE_BYTES(%d)", Integer.valueOf(content.length), 102400);
        this.versionCode = versionCode;
        this.content = (byte[]) zzu.zzu(content);
        this.type = (String) zzu.zzu(type);
        this.zzaby = namespace == null ? "" : namespace;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String getNamespace() {
        return this.zzaby;
    }

    public String getType() {
        return this.type;
    }

    public String toString() {
        return "Message{type='" + this.type + "', namespace='" + this.zzaby + "', content=[" + this.content.length + " bytes]}";
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zza.zza(this, out, flags);
    }

    public byte[] zzwV() {
        return this.content;
    }
}
