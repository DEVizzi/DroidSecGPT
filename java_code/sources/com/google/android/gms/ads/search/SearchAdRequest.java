package com.google.android.gms.ads.search;

import android.content.Context;
import android.graphics.Color;
import android.location.Location;
import android.os.Bundle;
import com.google.android.gms.ads.internal.client.zzx;
import com.google.android.gms.ads.mediation.MediationAdapter;
import com.google.android.gms.ads.mediation.NetworkExtras;
import com.google.android.gms.ads.mediation.customevent.CustomEvent;
/* loaded from: classes.dex */
public final class SearchAdRequest {
    public static final int BORDER_TYPE_DASHED = 1;
    public static final int BORDER_TYPE_DOTTED = 2;
    public static final int BORDER_TYPE_NONE = 0;
    public static final int BORDER_TYPE_SOLID = 3;
    public static final int CALL_BUTTON_COLOR_DARK = 2;
    public static final int CALL_BUTTON_COLOR_LIGHT = 0;
    public static final int CALL_BUTTON_COLOR_MEDIUM = 1;
    public static final String DEVICE_ID_EMULATOR = zzx.DEVICE_ID_EMULATOR;
    public static final int ERROR_CODE_INTERNAL_ERROR = 0;
    public static final int ERROR_CODE_INVALID_REQUEST = 1;
    public static final int ERROR_CODE_NETWORK_ERROR = 2;
    public static final int ERROR_CODE_NO_FILL = 3;
    private final int zzHN;
    private final int zzHO;
    private final int zzHP;
    private final int zzHQ;
    private final int zzHR;
    private final int zzHS;
    private final int zzHT;
    private final String zzHU;
    private final int zzHV;
    private final String zzHW;
    private final int zzHX;
    private final int zzHY;
    private final String zzHZ;
    private final zzx zznK;
    private final int zzvc;

    /* loaded from: classes.dex */
    public static final class Builder {
        private int zzHN;
        private int zzHO;
        private int zzHP;
        private int zzHQ;
        private int zzHR;
        private int zzHT;
        private String zzHU;
        private int zzHV;
        private String zzHW;
        private int zzHX;
        private int zzHY;
        private String zzHZ;
        private int zzvc;
        private final zzx.zza zznL = new zzx.zza();
        private int zzHS = 0;

        public Builder addCustomEventExtrasBundle(Class<? extends CustomEvent> adapterClass, Bundle customEventExtras) {
            this.zznL.zzb(adapterClass, customEventExtras);
            return this;
        }

        public Builder addNetworkExtras(NetworkExtras networkExtras) {
            this.zznL.zza(networkExtras);
            return this;
        }

        public Builder addNetworkExtrasBundle(Class<? extends MediationAdapter> adapterClass, Bundle networkExtras) {
            this.zznL.zza(adapterClass, networkExtras);
            return this;
        }

        public Builder addTestDevice(String deviceId) {
            this.zznL.zzF(deviceId);
            return this;
        }

        public SearchAdRequest build() {
            return new SearchAdRequest(this);
        }

        public Builder setAnchorTextColor(int anchorTextColor) {
            this.zzHN = anchorTextColor;
            return this;
        }

        public Builder setBackgroundColor(int backgroundColor) {
            this.zzvc = backgroundColor;
            this.zzHO = Color.argb(0, 0, 0, 0);
            this.zzHP = Color.argb(0, 0, 0, 0);
            return this;
        }

        public Builder setBackgroundGradient(int top, int bottom) {
            this.zzvc = Color.argb(0, 0, 0, 0);
            this.zzHO = bottom;
            this.zzHP = top;
            return this;
        }

        public Builder setBorderColor(int borderColor) {
            this.zzHQ = borderColor;
            return this;
        }

        public Builder setBorderThickness(int borderThickness) {
            this.zzHR = borderThickness;
            return this;
        }

        public Builder setBorderType(int borderType) {
            this.zzHS = borderType;
            return this;
        }

        public Builder setCallButtonColor(int callButtonColor) {
            this.zzHT = callButtonColor;
            return this;
        }

        public Builder setCustomChannels(String channelIds) {
            this.zzHU = channelIds;
            return this;
        }

        public Builder setDescriptionTextColor(int descriptionTextColor) {
            this.zzHV = descriptionTextColor;
            return this;
        }

        public Builder setFontFace(String fontFace) {
            this.zzHW = fontFace;
            return this;
        }

        public Builder setHeaderTextColor(int headerTextColor) {
            this.zzHX = headerTextColor;
            return this;
        }

        public Builder setHeaderTextSize(int headerTextSize) {
            this.zzHY = headerTextSize;
            return this;
        }

        public Builder setLocation(Location location) {
            this.zznL.zza(location);
            return this;
        }

        public Builder setQuery(String query) {
            this.zzHZ = query;
            return this;
        }

        public Builder setRequestAgent(String requestAgent) {
            this.zznL.zzJ(requestAgent);
            return this;
        }

        public Builder tagForChildDirectedTreatment(boolean tagForChildDirectedTreatment) {
            this.zznL.zzk(tagForChildDirectedTreatment);
            return this;
        }
    }

    private SearchAdRequest(Builder builder) {
        this.zzHN = builder.zzHN;
        this.zzvc = builder.zzvc;
        this.zzHO = builder.zzHO;
        this.zzHP = builder.zzHP;
        this.zzHQ = builder.zzHQ;
        this.zzHR = builder.zzHR;
        this.zzHS = builder.zzHS;
        this.zzHT = builder.zzHT;
        this.zzHU = builder.zzHU;
        this.zzHV = builder.zzHV;
        this.zzHW = builder.zzHW;
        this.zzHX = builder.zzHX;
        this.zzHY = builder.zzHY;
        this.zzHZ = builder.zzHZ;
        this.zznK = new zzx(builder.zznL, this);
    }

    public int getAnchorTextColor() {
        return this.zzHN;
    }

    public int getBackgroundColor() {
        return this.zzvc;
    }

    public int getBackgroundGradientBottom() {
        return this.zzHO;
    }

    public int getBackgroundGradientTop() {
        return this.zzHP;
    }

    public int getBorderColor() {
        return this.zzHQ;
    }

    public int getBorderThickness() {
        return this.zzHR;
    }

    public int getBorderType() {
        return this.zzHS;
    }

    public int getCallButtonColor() {
        return this.zzHT;
    }

    public String getCustomChannels() {
        return this.zzHU;
    }

    public <T extends CustomEvent> Bundle getCustomEventExtrasBundle(Class<T> adapterClass) {
        return this.zznK.getCustomEventExtrasBundle(adapterClass);
    }

    public int getDescriptionTextColor() {
        return this.zzHV;
    }

    public String getFontFace() {
        return this.zzHW;
    }

    public int getHeaderTextColor() {
        return this.zzHX;
    }

    public int getHeaderTextSize() {
        return this.zzHY;
    }

    public Location getLocation() {
        return this.zznK.getLocation();
    }

    @Deprecated
    public <T extends NetworkExtras> T getNetworkExtras(Class<T> networkExtrasClass) {
        return (T) this.zznK.getNetworkExtras(networkExtrasClass);
    }

    public <T extends MediationAdapter> Bundle getNetworkExtrasBundle(Class<T> adapterClass) {
        return this.zznK.getNetworkExtrasBundle(adapterClass);
    }

    public String getQuery() {
        return this.zzHZ;
    }

    public boolean isTestDevice(Context context) {
        return this.zznK.isTestDevice(context);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzx zzaF() {
        return this.zznK;
    }
}
