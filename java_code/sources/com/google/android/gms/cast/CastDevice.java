package com.google.android.gms.cast;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.cast.internal.zzf;
import com.google.android.gms.common.images.WebImage;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
/* loaded from: classes.dex */
public class CastDevice implements SafeParcelable {
    public static final int CAPABILITY_AUDIO_IN = 8;
    public static final int CAPABILITY_AUDIO_OUT = 4;
    public static final int CAPABILITY_VIDEO_IN = 2;
    public static final int CAPABILITY_VIDEO_OUT = 1;
    public static final Parcelable.Creator<CastDevice> CREATOR = new zzb();
    private final int zzCY;
    private String zzQL;
    String zzQM;
    private Inet4Address zzQN;
    private String zzQO;
    private String zzQP;
    private String zzQQ;
    private int zzQR;
    private List<WebImage> zzQS;
    private int zzQT;
    private int zzwS;

    private CastDevice() {
        this(3, null, null, null, null, null, -1, new ArrayList(), 0, -1);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CastDevice(int versionCode, String deviceId, String hostAddress, String friendlyName, String modelName, String deviceVersion, int servicePort, List<WebImage> icons, int capabilities, int status) {
        this.zzCY = versionCode;
        this.zzQL = deviceId;
        this.zzQM = hostAddress;
        if (this.zzQM != null) {
            try {
                InetAddress byName = InetAddress.getByName(this.zzQM);
                if (byName instanceof Inet4Address) {
                    this.zzQN = (Inet4Address) byName;
                }
            } catch (UnknownHostException e) {
                this.zzQN = null;
            }
        }
        this.zzQO = friendlyName;
        this.zzQP = modelName;
        this.zzQQ = deviceVersion;
        this.zzQR = servicePort;
        this.zzQS = icons;
        this.zzQT = capabilities;
        this.zzwS = status;
    }

    public static CastDevice getFromBundle(Bundle extras) {
        if (extras == null) {
            return null;
        }
        extras.setClassLoader(CastDevice.class.getClassLoader());
        return (CastDevice) extras.getParcelable("com.google.android.gms.cast.EXTRA_CAST_DEVICE");
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof CastDevice) {
            CastDevice castDevice = (CastDevice) obj;
            return getDeviceId() == null ? castDevice.getDeviceId() == null : zzf.zza(this.zzQL, castDevice.zzQL) && zzf.zza(this.zzQN, castDevice.zzQN) && zzf.zza(this.zzQP, castDevice.zzQP) && zzf.zza(this.zzQO, castDevice.zzQO) && zzf.zza(this.zzQQ, castDevice.zzQQ) && this.zzQR == castDevice.zzQR && zzf.zza(this.zzQS, castDevice.zzQS) && this.zzQT == castDevice.zzQT && this.zzwS == castDevice.zzwS;
        }
        return false;
    }

    public int getCapabilities() {
        return this.zzQT;
    }

    public String getDeviceId() {
        return this.zzQL;
    }

    public String getDeviceVersion() {
        return this.zzQQ;
    }

    public String getFriendlyName() {
        return this.zzQO;
    }

    public WebImage getIcon(int preferredWidth, int preferredHeight) {
        WebImage webImage;
        WebImage webImage2 = null;
        if (this.zzQS.isEmpty()) {
            return null;
        }
        if (preferredWidth <= 0 || preferredHeight <= 0) {
            return this.zzQS.get(0);
        }
        WebImage webImage3 = null;
        for (WebImage webImage4 : this.zzQS) {
            int width = webImage4.getWidth();
            int height = webImage4.getHeight();
            if (width < preferredWidth || height < preferredHeight) {
                if (width < preferredWidth && height < preferredHeight && (webImage2 == null || (webImage2.getWidth() < width && webImage2.getHeight() < height))) {
                    webImage = webImage3;
                    webImage3 = webImage;
                    webImage2 = webImage4;
                }
                webImage4 = webImage2;
                webImage = webImage3;
                webImage3 = webImage;
                webImage2 = webImage4;
            } else {
                if (webImage3 == null || (webImage3.getWidth() > width && webImage3.getHeight() > height)) {
                    WebImage webImage5 = webImage2;
                    webImage = webImage4;
                    webImage4 = webImage5;
                    webImage3 = webImage;
                    webImage2 = webImage4;
                }
                webImage4 = webImage2;
                webImage = webImage3;
                webImage3 = webImage;
                webImage2 = webImage4;
            }
        }
        if (webImage3 == null) {
            webImage3 = webImage2 != null ? webImage2 : this.zzQS.get(0);
        }
        return webImage3;
    }

    public List<WebImage> getIcons() {
        return Collections.unmodifiableList(this.zzQS);
    }

    public Inet4Address getIpAddress() {
        return this.zzQN;
    }

    public String getModelName() {
        return this.zzQP;
    }

    public int getServicePort() {
        return this.zzQR;
    }

    public int getStatus() {
        return this.zzwS;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public boolean hasCapabilities(int[] capabilities) {
        if (capabilities == null) {
            return false;
        }
        for (int i : capabilities) {
            if (!hasCapability(i)) {
                return false;
            }
        }
        return true;
    }

    public boolean hasCapability(int capability) {
        return (this.zzQT & capability) == capability;
    }

    public boolean hasIcons() {
        return !this.zzQS.isEmpty();
    }

    public int hashCode() {
        if (this.zzQL == null) {
            return 0;
        }
        return this.zzQL.hashCode();
    }

    public boolean isOnLocalNetwork() {
        return !this.zzQL.startsWith("__cast_nearby__");
    }

    public boolean isSameDevice(CastDevice castDevice) {
        if (castDevice == null) {
            return false;
        }
        return getDeviceId() == null ? castDevice.getDeviceId() == null : zzf.zza(getDeviceId(), castDevice.getDeviceId());
    }

    public void putInBundle(Bundle bundle) {
        if (bundle == null) {
            return;
        }
        bundle.putParcelable("com.google.android.gms.cast.EXTRA_CAST_DEVICE", this);
    }

    public String toString() {
        return String.format("\"%s\" (%s)", this.zzQO, this.zzQL);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzb.zza(this, out, flags);
    }
}
