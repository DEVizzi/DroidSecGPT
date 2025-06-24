package com.google.android.gms.maps;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.os.RemoteException;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.dynamic.zze;
import com.google.android.gms.dynamic.zzf;
import com.google.android.gms.maps.internal.IGoogleMapDelegate;
import com.google.android.gms.maps.internal.IMapViewDelegate;
import com.google.android.gms.maps.internal.MapLifecycleDelegate;
import com.google.android.gms.maps.internal.zzm;
import com.google.android.gms.maps.internal.zzy;
import com.google.android.gms.maps.model.RuntimeRemoteException;
import java.util.ArrayList;
import java.util.List;
/* loaded from: classes.dex */
public class MapView extends FrameLayout {
    private GoogleMap zzaBV;
    private final zzb zzaCb;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class zza implements MapLifecycleDelegate {
        private final ViewGroup zzaCc;
        private final IMapViewDelegate zzaCd;
        private View zzaCe;

        public zza(ViewGroup viewGroup, IMapViewDelegate iMapViewDelegate) {
            this.zzaCd = (IMapViewDelegate) zzu.zzu(iMapViewDelegate);
            this.zzaCc = (ViewGroup) zzu.zzu(viewGroup);
        }

        @Override // com.google.android.gms.maps.internal.MapLifecycleDelegate
        public void getMapAsync(final OnMapReadyCallback callback) {
            try {
                this.zzaCd.getMapAsync(new zzm.zza() { // from class: com.google.android.gms.maps.MapView.zza.1
                    @Override // com.google.android.gms.maps.internal.zzm
                    public void zza(IGoogleMapDelegate iGoogleMapDelegate) throws RemoteException {
                        callback.onMapReady(new GoogleMap(iGoogleMapDelegate));
                    }
                });
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        @Override // com.google.android.gms.dynamic.LifecycleDelegate
        public void onCreate(Bundle savedInstanceState) {
            try {
                this.zzaCd.onCreate(savedInstanceState);
                this.zzaCe = (View) zze.zzn(this.zzaCd.getView());
                this.zzaCc.removeAllViews();
                this.zzaCc.addView(this.zzaCe);
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        @Override // com.google.android.gms.dynamic.LifecycleDelegate
        public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
            throw new UnsupportedOperationException("onCreateView not allowed on MapViewDelegate");
        }

        @Override // com.google.android.gms.dynamic.LifecycleDelegate
        public void onDestroy() {
            try {
                this.zzaCd.onDestroy();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        @Override // com.google.android.gms.dynamic.LifecycleDelegate
        public void onDestroyView() {
            throw new UnsupportedOperationException("onDestroyView not allowed on MapViewDelegate");
        }

        @Override // com.google.android.gms.dynamic.LifecycleDelegate
        public void onInflate(Activity activity, Bundle attrs, Bundle savedInstanceState) {
            throw new UnsupportedOperationException("onInflate not allowed on MapViewDelegate");
        }

        @Override // com.google.android.gms.dynamic.LifecycleDelegate
        public void onLowMemory() {
            try {
                this.zzaCd.onLowMemory();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        @Override // com.google.android.gms.dynamic.LifecycleDelegate
        public void onPause() {
            try {
                this.zzaCd.onPause();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        @Override // com.google.android.gms.dynamic.LifecycleDelegate
        public void onResume() {
            try {
                this.zzaCd.onResume();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        @Override // com.google.android.gms.dynamic.LifecycleDelegate
        public void onSaveInstanceState(Bundle outState) {
            try {
                this.zzaCd.onSaveInstanceState(outState);
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        @Override // com.google.android.gms.dynamic.LifecycleDelegate
        public void onStart() {
        }

        @Override // com.google.android.gms.dynamic.LifecycleDelegate
        public void onStop() {
        }

        public IMapViewDelegate zzvv() {
            return this.zzaCd;
        }
    }

    /* loaded from: classes.dex */
    static class zzb extends com.google.android.gms.dynamic.zza<zza> {
        private final Context mContext;
        protected zzf<zza> zzaBZ;
        private final List<OnMapReadyCallback> zzaCa = new ArrayList();
        private final ViewGroup zzaCg;
        private final GoogleMapOptions zzaCh;

        zzb(ViewGroup viewGroup, Context context, GoogleMapOptions googleMapOptions) {
            this.zzaCg = viewGroup;
            this.mContext = context;
            this.zzaCh = googleMapOptions;
        }

        public void getMapAsync(OnMapReadyCallback callback) {
            if (zzqj() != null) {
                zzqj().getMapAsync(callback);
            } else {
                this.zzaCa.add(callback);
            }
        }

        @Override // com.google.android.gms.dynamic.zza
        protected void zza(zzf<zza> zzfVar) {
            this.zzaBZ = zzfVar;
            zzvu();
        }

        public void zzvu() {
            if (this.zzaBZ == null || zzqj() != null) {
                return;
            }
            try {
                MapsInitializer.initialize(this.mContext);
                IMapViewDelegate zza = zzy.zzay(this.mContext).zza(zze.zzw(this.mContext), this.zzaCh);
                if (zza == null) {
                    return;
                }
                this.zzaBZ.zza(new zza(this.zzaCg, zza));
                for (OnMapReadyCallback onMapReadyCallback : this.zzaCa) {
                    zzqj().getMapAsync(onMapReadyCallback);
                }
                this.zzaCa.clear();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            } catch (GooglePlayServicesNotAvailableException e2) {
            }
        }
    }

    public MapView(Context context) {
        super(context);
        this.zzaCb = new zzb(this, context, null);
        init();
    }

    public MapView(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.zzaCb = new zzb(this, context, GoogleMapOptions.createFromAttributes(context, attrs));
        init();
    }

    public MapView(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
        this.zzaCb = new zzb(this, context, GoogleMapOptions.createFromAttributes(context, attrs));
        init();
    }

    public MapView(Context context, GoogleMapOptions options) {
        super(context);
        this.zzaCb = new zzb(this, context, options);
        init();
    }

    private void init() {
        setClickable(true);
    }

    @Deprecated
    public final GoogleMap getMap() {
        if (this.zzaBV != null) {
            return this.zzaBV;
        }
        this.zzaCb.zzvu();
        if (this.zzaCb.zzqj() == null) {
            return null;
        }
        try {
            this.zzaBV = new GoogleMap(this.zzaCb.zzqj().zzvv().getMap());
            return this.zzaBV;
        } catch (RemoteException e) {
            throw new RuntimeRemoteException(e);
        }
    }

    public void getMapAsync(OnMapReadyCallback callback) {
        zzu.zzbY("getMapAsync() must be called on the main thread");
        this.zzaCb.getMapAsync(callback);
    }

    public final void onCreate(Bundle savedInstanceState) {
        this.zzaCb.onCreate(savedInstanceState);
        if (this.zzaCb.zzqj() == null) {
            com.google.android.gms.dynamic.zza.zzb(this);
        }
    }

    public final void onDestroy() {
        this.zzaCb.onDestroy();
    }

    public final void onLowMemory() {
        this.zzaCb.onLowMemory();
    }

    public final void onPause() {
        this.zzaCb.onPause();
    }

    public final void onResume() {
        this.zzaCb.onResume();
    }

    public final void onSaveInstanceState(Bundle outState) {
        this.zzaCb.onSaveInstanceState(outState);
    }
}
