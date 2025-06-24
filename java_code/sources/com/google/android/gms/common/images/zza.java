package com.google.android.gms.common.images;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.widget.ImageView;
import com.google.android.gms.common.images.ImageManager;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.internal.zzkg;
import com.google.android.gms.internal.zzkh;
import com.google.android.gms.internal.zzki;
import com.google.android.gms.internal.zzkj;
import java.lang.ref.WeakReference;
/* loaded from: classes.dex */
public abstract class zza {
    final C0033zza zzZc;
    protected int zzZe;
    protected ImageManager.OnImageLoadedListener zzZg;
    protected int zzZk;
    protected int zzZd = 0;
    protected boolean zzZf = false;
    private boolean zzZh = true;
    private boolean zzZi = false;
    private boolean zzZj = true;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: com.google.android.gms.common.images.zza$zza  reason: collision with other inner class name */
    /* loaded from: classes.dex */
    public static final class C0033zza {
        public final Uri uri;

        public C0033zza(Uri uri) {
            this.uri = uri;
        }

        public boolean equals(Object obj) {
            if (obj instanceof C0033zza) {
                if (this == obj) {
                    return true;
                }
                return zzt.equal(((C0033zza) obj).uri, this.uri);
            }
            return false;
        }

        public int hashCode() {
            return zzt.hashCode(this.uri);
        }
    }

    /* loaded from: classes.dex */
    public static final class zzb extends zza {
        private WeakReference<ImageView> zzZl;

        public zzb(ImageView imageView, int i) {
            super(null, i);
            com.google.android.gms.common.internal.zzb.zzq(imageView);
            this.zzZl = new WeakReference<>(imageView);
        }

        public zzb(ImageView imageView, Uri uri) {
            super(uri, 0);
            com.google.android.gms.common.internal.zzb.zzq(imageView);
            this.zzZl = new WeakReference<>(imageView);
        }

        private void zza(ImageView imageView, Drawable drawable, boolean z, boolean z2, boolean z3) {
            boolean z4 = (z2 || z3) ? false : true;
            if (z4 && (imageView instanceof zzki)) {
                int zznr = ((zzki) imageView).zznr();
                if (this.zzZe != 0 && zznr == this.zzZe) {
                    return;
                }
            }
            boolean zzb = zzb(z, z2);
            Drawable newDrawable = (!this.zzZf || drawable == null) ? drawable : drawable.getConstantState().newDrawable();
            if (zzb) {
                newDrawable = zza(imageView.getDrawable(), newDrawable);
            }
            imageView.setImageDrawable(newDrawable);
            if (imageView instanceof zzki) {
                zzki zzkiVar = (zzki) imageView;
                zzkiVar.zzi(z3 ? this.zzZc.uri : null);
                zzkiVar.zzbo(z4 ? this.zzZe : 0);
            }
            if (zzb) {
                ((zzkg) newDrawable).startTransition(250);
            }
        }

        public boolean equals(Object obj) {
            if (obj instanceof zzb) {
                if (this == obj) {
                    return true;
                }
                ImageView imageView = this.zzZl.get();
                ImageView imageView2 = ((zzb) obj).zzZl.get();
                return (imageView2 == null || imageView == null || !zzt.equal(imageView2, imageView)) ? false : true;
            }
            return false;
        }

        public int hashCode() {
            return 0;
        }

        @Override // com.google.android.gms.common.images.zza
        protected void zza(Drawable drawable, boolean z, boolean z2, boolean z3) {
            ImageView imageView = this.zzZl.get();
            if (imageView != null) {
                zza(imageView, drawable, z, z2, z3);
            }
        }
    }

    /* loaded from: classes.dex */
    public static final class zzc extends zza {
        private WeakReference<ImageManager.OnImageLoadedListener> zzZm;

        public zzc(ImageManager.OnImageLoadedListener onImageLoadedListener, Uri uri) {
            super(uri, 0);
            com.google.android.gms.common.internal.zzb.zzq(onImageLoadedListener);
            this.zzZm = new WeakReference<>(onImageLoadedListener);
        }

        public boolean equals(Object obj) {
            if (obj instanceof zzc) {
                if (this == obj) {
                    return true;
                }
                zzc zzcVar = (zzc) obj;
                ImageManager.OnImageLoadedListener onImageLoadedListener = this.zzZm.get();
                ImageManager.OnImageLoadedListener onImageLoadedListener2 = zzcVar.zzZm.get();
                return onImageLoadedListener2 != null && onImageLoadedListener != null && zzt.equal(onImageLoadedListener2, onImageLoadedListener) && zzt.equal(zzcVar.zzZc, this.zzZc);
            }
            return false;
        }

        public int hashCode() {
            return zzt.hashCode(this.zzZc);
        }

        @Override // com.google.android.gms.common.images.zza
        protected void zza(Drawable drawable, boolean z, boolean z2, boolean z3) {
            ImageManager.OnImageLoadedListener onImageLoadedListener;
            if (z2 || (onImageLoadedListener = this.zzZm.get()) == null) {
                return;
            }
            onImageLoadedListener.onImageLoaded(this.zzZc.uri, drawable, z3);
        }
    }

    public zza(Uri uri, int i) {
        this.zzZe = 0;
        this.zzZc = new C0033zza(uri);
        this.zzZe = i;
    }

    private Drawable zza(Context context, zzkj zzkjVar, int i) {
        Resources resources = context.getResources();
        if (this.zzZk > 0) {
            zzkj.zza zzaVar = new zzkj.zza(i, this.zzZk);
            Drawable drawable = zzkjVar.get(zzaVar);
            if (drawable == null) {
                Drawable drawable2 = resources.getDrawable(i);
                if ((this.zzZk & 1) != 0) {
                    drawable2 = zza(resources, drawable2);
                }
                zzkjVar.put(zzaVar, drawable2);
                return drawable2;
            }
            return drawable;
        }
        return resources.getDrawable(i);
    }

    protected Drawable zza(Resources resources, Drawable drawable) {
        return zzkh.zza(resources, drawable);
    }

    protected zzkg zza(Drawable drawable, Drawable drawable2) {
        if (drawable == null) {
            drawable = null;
        } else if (drawable instanceof zzkg) {
            drawable = ((zzkg) drawable).zznp();
        }
        return new zzkg(drawable, drawable2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zza(Context context, Bitmap bitmap, boolean z) {
        com.google.android.gms.common.internal.zzb.zzq(bitmap);
        if ((this.zzZk & 1) != 0) {
            bitmap = zzkh.zza(bitmap);
        }
        BitmapDrawable bitmapDrawable = new BitmapDrawable(context.getResources(), bitmap);
        if (this.zzZg != null) {
            this.zzZg.onImageLoaded(this.zzZc.uri, bitmapDrawable, true);
        }
        zza(bitmapDrawable, z, false, true);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zza(Context context, zzkj zzkjVar) {
        if (this.zzZj) {
            zza(this.zzZd != 0 ? zza(context, zzkjVar, this.zzZd) : null, false, true, false);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zza(Context context, zzkj zzkjVar, boolean z) {
        Drawable zza = this.zzZe != 0 ? zza(context, zzkjVar, this.zzZe) : null;
        if (this.zzZg != null) {
            this.zzZg.onImageLoaded(this.zzZc.uri, zza, false);
        }
        zza(zza, z, false, false);
    }

    protected abstract void zza(Drawable drawable, boolean z, boolean z2, boolean z3);

    protected boolean zzb(boolean z, boolean z2) {
        return this.zzZh && !z2 && (!z || this.zzZi);
    }

    public void zzbm(int i) {
        this.zzZe = i;
    }
}
