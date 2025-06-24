package com.google.android.gms.internal;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.SystemClock;
/* loaded from: classes.dex */
public final class zzkg extends Drawable implements Drawable.Callback {
    private int mFrom;
    private long zzKT;
    private int zzZA;
    private boolean zzZh;
    private int zzZo;
    private int zzZp;
    private int zzZq;
    private int zzZr;
    private int zzZs;
    private boolean zzZt;
    private zzb zzZu;
    private Drawable zzZv;
    private Drawable zzZw;
    private boolean zzZx;
    private boolean zzZy;
    private boolean zzZz;

    /* loaded from: classes.dex */
    private static final class zza extends Drawable {
        private static final zza zzZB = new zza();
        private static final C0118zza zzZC = new C0118zza();

        /* renamed from: com.google.android.gms.internal.zzkg$zza$zza  reason: collision with other inner class name */
        /* loaded from: classes.dex */
        private static final class C0118zza extends Drawable.ConstantState {
            private C0118zza() {
            }

            @Override // android.graphics.drawable.Drawable.ConstantState
            public int getChangingConfigurations() {
                return 0;
            }

            @Override // android.graphics.drawable.Drawable.ConstantState
            public Drawable newDrawable() {
                return zza.zzZB;
            }
        }

        private zza() {
        }

        @Override // android.graphics.drawable.Drawable
        public void draw(Canvas canvas) {
        }

        @Override // android.graphics.drawable.Drawable
        public Drawable.ConstantState getConstantState() {
            return zzZC;
        }

        @Override // android.graphics.drawable.Drawable
        public int getOpacity() {
            return -2;
        }

        @Override // android.graphics.drawable.Drawable
        public void setAlpha(int alpha) {
        }

        @Override // android.graphics.drawable.Drawable
        public void setColorFilter(ColorFilter cf) {
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzb extends Drawable.ConstantState {
        int zzZD;
        int zzZE;

        zzb(zzb zzbVar) {
            if (zzbVar != null) {
                this.zzZD = zzbVar.zzZD;
                this.zzZE = zzbVar.zzZE;
            }
        }

        @Override // android.graphics.drawable.Drawable.ConstantState
        public int getChangingConfigurations() {
            return this.zzZD;
        }

        @Override // android.graphics.drawable.Drawable.ConstantState
        public Drawable newDrawable() {
            return new zzkg(this);
        }
    }

    public zzkg(Drawable drawable, Drawable drawable2) {
        this(null);
        drawable = drawable == null ? zza.zzZB : drawable;
        this.zzZv = drawable;
        drawable.setCallback(this);
        this.zzZu.zzZE |= drawable.getChangingConfigurations();
        drawable2 = drawable2 == null ? zza.zzZB : drawable2;
        this.zzZw = drawable2;
        drawable2.setCallback(this);
        this.zzZu.zzZE |= drawable2.getChangingConfigurations();
    }

    zzkg(zzb zzbVar) {
        this.zzZo = 0;
        this.zzZq = 255;
        this.zzZs = 0;
        this.zzZh = true;
        this.zzZu = new zzb(zzbVar);
    }

    public boolean canConstantState() {
        if (!this.zzZx) {
            this.zzZy = (this.zzZv.getConstantState() == null || this.zzZw.getConstantState() == null) ? false : true;
            this.zzZx = true;
        }
        return this.zzZy;
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        boolean z = false;
        switch (this.zzZo) {
            case 1:
                this.zzKT = SystemClock.uptimeMillis();
                this.zzZo = 2;
                break;
            case 2:
                if (this.zzKT >= 0) {
                    float uptimeMillis = ((float) (SystemClock.uptimeMillis() - this.zzKT)) / this.zzZr;
                    r1 = uptimeMillis >= 1.0f;
                    if (r1) {
                        this.zzZo = 0;
                    }
                    this.zzZs = (int) ((Math.min(uptimeMillis, 1.0f) * (this.zzZp - this.mFrom)) + this.mFrom);
                }
            default:
                z = r1;
                break;
        }
        int i = this.zzZs;
        boolean z2 = this.zzZh;
        Drawable drawable = this.zzZv;
        Drawable drawable2 = this.zzZw;
        if (z) {
            if (!z2 || i == 0) {
                drawable.draw(canvas);
            }
            if (i == this.zzZq) {
                drawable2.setAlpha(this.zzZq);
                drawable2.draw(canvas);
                return;
            }
            return;
        }
        if (z2) {
            drawable.setAlpha(this.zzZq - i);
        }
        drawable.draw(canvas);
        if (z2) {
            drawable.setAlpha(this.zzZq);
        }
        if (i > 0) {
            drawable2.setAlpha(i);
            drawable2.draw(canvas);
            drawable2.setAlpha(this.zzZq);
        }
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public int getChangingConfigurations() {
        return super.getChangingConfigurations() | this.zzZu.zzZD | this.zzZu.zzZE;
    }

    @Override // android.graphics.drawable.Drawable
    public Drawable.ConstantState getConstantState() {
        if (canConstantState()) {
            this.zzZu.zzZD = getChangingConfigurations();
            return this.zzZu;
        }
        return null;
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        return Math.max(this.zzZv.getIntrinsicHeight(), this.zzZw.getIntrinsicHeight());
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        return Math.max(this.zzZv.getIntrinsicWidth(), this.zzZw.getIntrinsicWidth());
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        if (!this.zzZz) {
            this.zzZA = Drawable.resolveOpacity(this.zzZv.getOpacity(), this.zzZw.getOpacity());
            this.zzZz = true;
        }
        return this.zzZA;
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public void invalidateDrawable(Drawable who) {
        Drawable.Callback callback;
        if (!zzlk.zzoR() || (callback = getCallback()) == null) {
            return;
        }
        callback.invalidateDrawable(this);
    }

    @Override // android.graphics.drawable.Drawable
    public Drawable mutate() {
        if (!this.zzZt && super.mutate() == this) {
            if (!canConstantState()) {
                throw new IllegalStateException("One or more children of this LayerDrawable does not have constant state; this drawable cannot be mutated.");
            }
            this.zzZv.mutate();
            this.zzZw.mutate();
            this.zzZt = true;
        }
        return this;
    }

    @Override // android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect bounds) {
        this.zzZv.setBounds(bounds);
        this.zzZw.setBounds(bounds);
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public void scheduleDrawable(Drawable who, Runnable what, long when) {
        Drawable.Callback callback;
        if (!zzlk.zzoR() || (callback = getCallback()) == null) {
            return;
        }
        callback.scheduleDrawable(this, what, when);
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int alpha) {
        if (this.zzZs == this.zzZq) {
            this.zzZs = alpha;
        }
        this.zzZq = alpha;
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter cf) {
        this.zzZv.setColorFilter(cf);
        this.zzZw.setColorFilter(cf);
    }

    public void startTransition(int durationMillis) {
        this.mFrom = 0;
        this.zzZp = this.zzZq;
        this.zzZs = 0;
        this.zzZr = durationMillis;
        this.zzZo = 1;
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public void unscheduleDrawable(Drawable who, Runnable what) {
        Drawable.Callback callback;
        if (!zzlk.zzoR() || (callback = getCallback()) == null) {
            return;
        }
        callback.unscheduleDrawable(this, what);
    }

    public Drawable zznp() {
        return this.zzZw;
    }
}
