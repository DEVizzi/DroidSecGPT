package com.google.android.gms.dynamic;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.google.android.gms.dynamic.LifecycleDelegate;
import java.util.Iterator;
import java.util.LinkedList;
/* loaded from: classes.dex */
public abstract class zza<T extends LifecycleDelegate> {
    private T zzajh;
    private Bundle zzaji;
    private LinkedList<InterfaceC0060zza> zzajj;
    private final zzf<T> zzajk = (zzf<T>) new zzf<T>() { // from class: com.google.android.gms.dynamic.zza.1
        @Override // com.google.android.gms.dynamic.zzf
        public void zza(T t) {
            zza.this.zzajh = t;
            Iterator it = zza.this.zzajj.iterator();
            while (it.hasNext()) {
                ((InterfaceC0060zza) it.next()).zzb(zza.this.zzajh);
            }
            zza.this.zzajj.clear();
            zza.this.zzaji = null;
        }
    };

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: com.google.android.gms.dynamic.zza$zza  reason: collision with other inner class name */
    /* loaded from: classes.dex */
    public interface InterfaceC0060zza {
        int getState();

        void zzb(LifecycleDelegate lifecycleDelegate);
    }

    private void zza(Bundle bundle, InterfaceC0060zza interfaceC0060zza) {
        if (this.zzajh != null) {
            interfaceC0060zza.zzb(this.zzajh);
            return;
        }
        if (this.zzajj == null) {
            this.zzajj = new LinkedList<>();
        }
        this.zzajj.add(interfaceC0060zza);
        if (bundle != null) {
            if (this.zzaji == null) {
                this.zzaji = (Bundle) bundle.clone();
            } else {
                this.zzaji.putAll(bundle);
            }
        }
        zza(this.zzajk);
    }

    public static void zzb(FrameLayout frameLayout) {
        final Context context = frameLayout.getContext();
        final int isGooglePlayServicesAvailable = GooglePlayServicesUtil.isGooglePlayServicesAvailable(context);
        String zzb = com.google.android.gms.common.internal.zzf.zzb(context, isGooglePlayServicesAvailable, GooglePlayServicesUtil.zzad(context));
        String zzh = com.google.android.gms.common.internal.zzf.zzh(context, isGooglePlayServicesAvailable);
        LinearLayout linearLayout = new LinearLayout(frameLayout.getContext());
        linearLayout.setOrientation(1);
        linearLayout.setLayoutParams(new FrameLayout.LayoutParams(-2, -2));
        frameLayout.addView(linearLayout);
        TextView textView = new TextView(frameLayout.getContext());
        textView.setLayoutParams(new FrameLayout.LayoutParams(-2, -2));
        textView.setText(zzb);
        linearLayout.addView(textView);
        if (zzh != null) {
            Button button = new Button(context);
            button.setLayoutParams(new FrameLayout.LayoutParams(-2, -2));
            button.setText(zzh);
            linearLayout.addView(button);
            button.setOnClickListener(new View.OnClickListener() { // from class: com.google.android.gms.dynamic.zza.5
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    context.startActivity(GooglePlayServicesUtil.zzaT(isGooglePlayServicesAvailable));
                }
            });
        }
    }

    private void zzdY(int i) {
        while (!this.zzajj.isEmpty() && this.zzajj.getLast().getState() >= i) {
            this.zzajj.removeLast();
        }
    }

    public void onCreate(final Bundle savedInstanceState) {
        zza(savedInstanceState, new InterfaceC0060zza() { // from class: com.google.android.gms.dynamic.zza.3
            @Override // com.google.android.gms.dynamic.zza.InterfaceC0060zza
            public int getState() {
                return 1;
            }

            @Override // com.google.android.gms.dynamic.zza.InterfaceC0060zza
            public void zzb(LifecycleDelegate lifecycleDelegate) {
                zza.this.zzajh.onCreate(savedInstanceState);
            }
        });
    }

    public View onCreateView(final LayoutInflater inflater, final ViewGroup container, final Bundle savedInstanceState) {
        final FrameLayout frameLayout = new FrameLayout(inflater.getContext());
        zza(savedInstanceState, new InterfaceC0060zza() { // from class: com.google.android.gms.dynamic.zza.4
            @Override // com.google.android.gms.dynamic.zza.InterfaceC0060zza
            public int getState() {
                return 2;
            }

            @Override // com.google.android.gms.dynamic.zza.InterfaceC0060zza
            public void zzb(LifecycleDelegate lifecycleDelegate) {
                frameLayout.removeAllViews();
                frameLayout.addView(zza.this.zzajh.onCreateView(inflater, container, savedInstanceState));
            }
        });
        if (this.zzajh == null) {
            zza(frameLayout);
        }
        return frameLayout;
    }

    public void onDestroy() {
        if (this.zzajh != null) {
            this.zzajh.onDestroy();
        } else {
            zzdY(1);
        }
    }

    public void onDestroyView() {
        if (this.zzajh != null) {
            this.zzajh.onDestroyView();
        } else {
            zzdY(2);
        }
    }

    public void onInflate(final Activity activity, final Bundle attrs, final Bundle savedInstanceState) {
        zza(savedInstanceState, new InterfaceC0060zza() { // from class: com.google.android.gms.dynamic.zza.2
            @Override // com.google.android.gms.dynamic.zza.InterfaceC0060zza
            public int getState() {
                return 0;
            }

            @Override // com.google.android.gms.dynamic.zza.InterfaceC0060zza
            public void zzb(LifecycleDelegate lifecycleDelegate) {
                zza.this.zzajh.onInflate(activity, attrs, savedInstanceState);
            }
        });
    }

    public void onLowMemory() {
        if (this.zzajh != null) {
            this.zzajh.onLowMemory();
        }
    }

    public void onPause() {
        if (this.zzajh != null) {
            this.zzajh.onPause();
        } else {
            zzdY(5);
        }
    }

    public void onResume() {
        zza((Bundle) null, new InterfaceC0060zza() { // from class: com.google.android.gms.dynamic.zza.7
            @Override // com.google.android.gms.dynamic.zza.InterfaceC0060zza
            public int getState() {
                return 5;
            }

            @Override // com.google.android.gms.dynamic.zza.InterfaceC0060zza
            public void zzb(LifecycleDelegate lifecycleDelegate) {
                zza.this.zzajh.onResume();
            }
        });
    }

    public void onSaveInstanceState(Bundle outState) {
        if (this.zzajh != null) {
            this.zzajh.onSaveInstanceState(outState);
        } else if (this.zzaji != null) {
            outState.putAll(this.zzaji);
        }
    }

    public void onStart() {
        zza((Bundle) null, new InterfaceC0060zza() { // from class: com.google.android.gms.dynamic.zza.6
            @Override // com.google.android.gms.dynamic.zza.InterfaceC0060zza
            public int getState() {
                return 4;
            }

            @Override // com.google.android.gms.dynamic.zza.InterfaceC0060zza
            public void zzb(LifecycleDelegate lifecycleDelegate) {
                zza.this.zzajh.onStart();
            }
        });
    }

    public void onStop() {
        if (this.zzajh != null) {
            this.zzajh.onStop();
        } else {
            zzdY(4);
        }
    }

    protected void zza(FrameLayout frameLayout) {
        zzb(frameLayout);
    }

    protected abstract void zza(zzf<T> zzfVar);

    public T zzqj() {
        return this.zzajh;
    }
}
