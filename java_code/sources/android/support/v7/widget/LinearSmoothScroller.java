package android.support.v7.widget;

import android.content.Context;
import android.graphics.PointF;
import android.support.v7.widget.RecyclerView;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.LinearInterpolator;
/* loaded from: classes.dex */
public abstract class LinearSmoothScroller extends RecyclerView.SmoothScroller {
    private static final boolean DEBUG = false;
    private static final float MILLISECONDS_PER_INCH = 25.0f;
    public static final int SNAP_TO_ANY = 0;
    public static final int SNAP_TO_END = 1;
    public static final int SNAP_TO_START = -1;
    private static final String TAG = "LinearSmoothScroller";
    private static final float TARGET_SEEK_EXTRA_SCROLL_RATIO = 1.2f;
    private static final int TARGET_SEEK_SCROLL_DISTANCE_PX = 10000;
    private final float MILLISECONDS_PER_PX;
    protected PointF mTargetVector;
    protected final LinearInterpolator mLinearInterpolator = new LinearInterpolator();
    protected final DecelerateInterpolator mDecelerateInterpolator = new DecelerateInterpolator();
    protected int mInterimTargetDx = 0;
    protected int mInterimTargetDy = 0;

    public abstract PointF computeScrollVectorForPosition(int i);

    public LinearSmoothScroller(Context context) {
        this.MILLISECONDS_PER_PX = calculateSpeedPerPixel(context.getResources().getDisplayMetrics());
    }

    @Override // android.support.v7.widget.RecyclerView.SmoothScroller
    protected void onStart() {
    }

    @Override // android.support.v7.widget.RecyclerView.SmoothScroller
    protected void onTargetFound(View targetView, RecyclerView.State state, RecyclerView.SmoothScroller.Action action) {
        int dx = calculateDxToMakeVisible(targetView, getHorizontalSnapPreference());
        int dy = calculateDyToMakeVisible(targetView, getVerticalSnapPreference());
        int distance = (int) Math.sqrt((dx * dx) + (dy * dy));
        int time = calculateTimeForDeceleration(distance);
        if (time > 0) {
            action.update(-dx, -dy, time, this.mDecelerateInterpolator);
        }
    }

    @Override // android.support.v7.widget.RecyclerView.SmoothScroller
    protected void onSeekTargetStep(int dx, int dy, RecyclerView.State state, RecyclerView.SmoothScroller.Action action) {
        if (getChildCount() == 0) {
            stop();
            return;
        }
        this.mInterimTargetDx = clampApplyScroll(this.mInterimTargetDx, dx);
        this.mInterimTargetDy = clampApplyScroll(this.mInterimTargetDy, dy);
        if (this.mInterimTargetDx == 0 && this.mInterimTargetDy == 0) {
            updateActionForInterimTarget(action);
        }
    }

    @Override // android.support.v7.widget.RecyclerView.SmoothScroller
    protected void onStop() {
        this.mInterimTargetDy = 0;
        this.mInterimTargetDx = 0;
        this.mTargetVector = null;
    }

    protected float calculateSpeedPerPixel(DisplayMetrics displayMetrics) {
        return MILLISECONDS_PER_INCH / displayMetrics.densityDpi;
    }

    protected int calculateTimeForDeceleration(int dx) {
        return (int) Math.ceil(calculateTimeForScrolling(dx) / 0.3356d);
    }

    protected int calculateTimeForScrolling(int dx) {
        return (int) Math.ceil(Math.abs(dx) * this.MILLISECONDS_PER_PX);
    }

    protected int getHorizontalSnapPreference() {
        if (this.mTargetVector == null || this.mTargetVector.x == 0.0f) {
            return 0;
        }
        return this.mTargetVector.x > 0.0f ? 1 : -1;
    }

    protected int getVerticalSnapPreference() {
        if (this.mTargetVector == null || this.mTargetVector.y == 0.0f) {
            return 0;
        }
        return this.mTargetVector.y > 0.0f ? 1 : -1;
    }

    protected void updateActionForInterimTarget(RecyclerView.SmoothScroller.Action action) {
        PointF scrollVector = computeScrollVectorForPosition(getTargetPosition());
        if (scrollVector == null || (scrollVector.x == 0.0f && scrollVector.y == 0.0f)) {
            Log.e(TAG, "To support smooth scrolling, you should override \nLayoutManager#computeScrollVectorForPosition.\nFalling back to instant scroll");
            int target = getTargetPosition();
            action.jumpTo(target);
            stop();
            return;
        }
        normalize(scrollVector);
        this.mTargetVector = scrollVector;
        this.mInterimTargetDx = (int) (scrollVector.x * 10000.0f);
        this.mInterimTargetDy = (int) (scrollVector.y * 10000.0f);
        int time = calculateTimeForScrolling(TARGET_SEEK_SCROLL_DISTANCE_PX);
        action.update((int) (this.mInterimTargetDx * TARGET_SEEK_EXTRA_SCROLL_RATIO), (int) (this.mInterimTargetDy * TARGET_SEEK_EXTRA_SCROLL_RATIO), (int) (time * TARGET_SEEK_EXTRA_SCROLL_RATIO), this.mLinearInterpolator);
    }

    private int clampApplyScroll(int tmpDt, int dt) {
        int tmpDt2 = tmpDt - dt;
        if (tmpDt * tmpDt2 <= 0) {
            return 0;
        }
        return tmpDt2;
    }

    public int calculateDtToFit(int viewStart, int viewEnd, int boxStart, int boxEnd, int snapPreference) {
        switch (snapPreference) {
            case -1:
                return boxStart - viewStart;
            case 0:
                int dtStart = boxStart - viewStart;
                if (dtStart <= 0) {
                    int dtEnd = boxEnd - viewEnd;
                    if (dtEnd < 0) {
                        return dtEnd;
                    }
                    return 0;
                }
                return dtStart;
            case 1:
                return boxEnd - viewEnd;
            default:
                throw new IllegalArgumentException("snap preference should be one of the constants defined in SmoothScroller, starting with SNAP_");
        }
    }

    public int calculateDyToMakeVisible(View view, int snapPreference) {
        RecyclerView.LayoutManager layoutManager = getLayoutManager();
        if (!layoutManager.canScrollVertically()) {
            return 0;
        }
        RecyclerView.LayoutParams params = (RecyclerView.LayoutParams) view.getLayoutParams();
        int top = layoutManager.getDecoratedTop(view) - params.topMargin;
        int bottom = layoutManager.getDecoratedBottom(view) + params.bottomMargin;
        int start = layoutManager.getPaddingTop();
        int end = layoutManager.getHeight() - layoutManager.getPaddingBottom();
        return calculateDtToFit(top, bottom, start, end, snapPreference);
    }

    public int calculateDxToMakeVisible(View view, int snapPreference) {
        RecyclerView.LayoutManager layoutManager = getLayoutManager();
        if (!layoutManager.canScrollHorizontally()) {
            return 0;
        }
        RecyclerView.LayoutParams params = (RecyclerView.LayoutParams) view.getLayoutParams();
        int left = layoutManager.getDecoratedLeft(view) - params.leftMargin;
        int right = layoutManager.getDecoratedRight(view) + params.rightMargin;
        int start = layoutManager.getPaddingLeft();
        int end = layoutManager.getWidth() - layoutManager.getPaddingRight();
        return calculateDtToFit(left, right, start, end, snapPreference);
    }
}
