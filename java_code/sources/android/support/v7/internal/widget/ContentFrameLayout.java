package android.support.v7.internal.widget;

import android.content.Context;
import android.graphics.Rect;
import android.support.v4.view.ViewCompat;
import android.util.AttributeSet;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.View;
import android.widget.FrameLayout;
/* loaded from: classes.dex */
public class ContentFrameLayout extends FrameLayout {
    private OnAttachListener mAttachListener;
    private final Rect mDecorPadding;
    private TypedValue mFixedHeightMajor;
    private TypedValue mFixedHeightMinor;
    private TypedValue mFixedWidthMajor;
    private TypedValue mFixedWidthMinor;
    private TypedValue mMinWidthMajor;
    private TypedValue mMinWidthMinor;

    /* loaded from: classes.dex */
    public interface OnAttachListener {
        void onAttachedFromWindow();

        void onDetachedFromWindow();
    }

    public ContentFrameLayout(Context context) {
        this(context, null);
    }

    public ContentFrameLayout(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public ContentFrameLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mDecorPadding = new Rect();
    }

    public void dispatchFitSystemWindows(Rect insets) {
        fitSystemWindows(insets);
    }

    public void setAttachListener(OnAttachListener attachListener) {
        this.mAttachListener = attachListener;
    }

    public void setDecorPadding(int left, int top, int right, int bottom) {
        this.mDecorPadding.set(left, top, right, bottom);
        if (ViewCompat.isLaidOut(this)) {
            requestLayout();
        }
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        DisplayMetrics metrics = getContext().getResources().getDisplayMetrics();
        boolean isPortrait = metrics.widthPixels < metrics.heightPixels;
        int widthMode = View.MeasureSpec.getMode(widthMeasureSpec);
        int heightMode = View.MeasureSpec.getMode(heightMeasureSpec);
        boolean fixedWidth = false;
        if (widthMode == Integer.MIN_VALUE) {
            TypedValue tvw = isPortrait ? this.mFixedWidthMinor : this.mFixedWidthMajor;
            if (tvw != null && tvw.type != 0) {
                int w = 0;
                if (tvw.type == 5) {
                    w = (int) tvw.getDimension(metrics);
                } else if (tvw.type == 6) {
                    w = (int) tvw.getFraction(metrics.widthPixels, metrics.widthPixels);
                }
                if (w > 0) {
                    int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
                    widthMeasureSpec = View.MeasureSpec.makeMeasureSpec(Math.min(w - (this.mDecorPadding.left + this.mDecorPadding.right), widthSize), 1073741824);
                    fixedWidth = true;
                }
            }
        }
        if (heightMode == Integer.MIN_VALUE) {
            TypedValue tvh = isPortrait ? this.mFixedHeightMajor : this.mFixedHeightMinor;
            if (tvh != null && tvh.type != 0) {
                int h = 0;
                if (tvh.type == 5) {
                    h = (int) tvh.getDimension(metrics);
                } else if (tvh.type == 6) {
                    h = (int) tvh.getFraction(metrics.heightPixels, metrics.heightPixels);
                }
                if (h > 0) {
                    int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
                    heightMeasureSpec = View.MeasureSpec.makeMeasureSpec(Math.min(h - (this.mDecorPadding.top + this.mDecorPadding.bottom), heightSize), 1073741824);
                }
            }
        }
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        int width = getMeasuredWidth();
        boolean measure = false;
        int widthMeasureSpec2 = View.MeasureSpec.makeMeasureSpec(width, 1073741824);
        if (!fixedWidth && widthMode == Integer.MIN_VALUE) {
            TypedValue tv = isPortrait ? this.mMinWidthMinor : this.mMinWidthMajor;
            if (tv != null && tv.type != 0) {
                int min = 0;
                if (tv.type == 5) {
                    min = (int) tv.getDimension(metrics);
                } else if (tv.type == 6) {
                    min = (int) tv.getFraction(metrics.widthPixels, metrics.widthPixels);
                }
                if (min > 0) {
                    min -= this.mDecorPadding.left + this.mDecorPadding.right;
                }
                if (width < min) {
                    widthMeasureSpec2 = View.MeasureSpec.makeMeasureSpec(min, 1073741824);
                    measure = true;
                }
            }
        }
        if (measure) {
            super.onMeasure(widthMeasureSpec2, heightMeasureSpec);
        }
    }

    public TypedValue getMinWidthMajor() {
        if (this.mMinWidthMajor == null) {
            this.mMinWidthMajor = new TypedValue();
        }
        return this.mMinWidthMajor;
    }

    public TypedValue getMinWidthMinor() {
        if (this.mMinWidthMinor == null) {
            this.mMinWidthMinor = new TypedValue();
        }
        return this.mMinWidthMinor;
    }

    public TypedValue getFixedWidthMajor() {
        if (this.mFixedWidthMajor == null) {
            this.mFixedWidthMajor = new TypedValue();
        }
        return this.mFixedWidthMajor;
    }

    public TypedValue getFixedWidthMinor() {
        if (this.mFixedWidthMinor == null) {
            this.mFixedWidthMinor = new TypedValue();
        }
        return this.mFixedWidthMinor;
    }

    public TypedValue getFixedHeightMajor() {
        if (this.mFixedHeightMajor == null) {
            this.mFixedHeightMajor = new TypedValue();
        }
        return this.mFixedHeightMajor;
    }

    public TypedValue getFixedHeightMinor() {
        if (this.mFixedHeightMinor == null) {
            this.mFixedHeightMinor = new TypedValue();
        }
        return this.mFixedHeightMinor;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (this.mAttachListener != null) {
            this.mAttachListener.onAttachedFromWindow();
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (this.mAttachListener != null) {
            this.mAttachListener.onDetachedFromWindow();
        }
    }
}
