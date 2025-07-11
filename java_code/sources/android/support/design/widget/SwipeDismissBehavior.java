package android.support.design.widget;

import android.support.design.widget.CoordinatorLayout;
import android.support.v4.view.MotionEventCompat;
import android.support.v4.view.ViewCompat;
import android.support.v4.widget.ViewDragHelper;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
/* loaded from: classes.dex */
public class SwipeDismissBehavior<V extends View> extends CoordinatorLayout.Behavior<V> {
    private static final float DEFAULT_ALPHA_END_DISTANCE = 0.5f;
    private static final float DEFAULT_ALPHA_START_DISTANCE = 0.0f;
    private static final float DEFAULT_DRAG_DISMISS_THRESHOLD = 0.5f;
    public static final int STATE_DRAGGING = 1;
    public static final int STATE_IDLE = 0;
    public static final int STATE_SETTLING = 2;
    public static final int SWIPE_DIRECTION_ANY = 2;
    public static final int SWIPE_DIRECTION_END_TO_START = 1;
    public static final int SWIPE_DIRECTION_START_TO_END = 0;
    private boolean mIgnoreEvents;
    private OnDismissListener mListener;
    private boolean mSensitivitySet;
    private ViewDragHelper mViewDragHelper;
    private float mSensitivity = 0.0f;
    private int mSwipeDirection = 2;
    private float mDragDismissThreshold = 0.5f;
    private float mAlphaStartSwipeDistance = 0.0f;
    private float mAlphaEndSwipeDistance = 0.5f;
    private final ViewDragHelper.Callback mDragCallback = new ViewDragHelper.Callback() { // from class: android.support.design.widget.SwipeDismissBehavior.1
        private int mOriginalCapturedViewLeft;

        @Override // android.support.v4.widget.ViewDragHelper.Callback
        public boolean tryCaptureView(View child, int pointerId) {
            this.mOriginalCapturedViewLeft = child.getLeft();
            return true;
        }

        @Override // android.support.v4.widget.ViewDragHelper.Callback
        public void onViewDragStateChanged(int state) {
            if (SwipeDismissBehavior.this.mListener != null) {
                SwipeDismissBehavior.this.mListener.onDragStateChanged(state);
            }
        }

        @Override // android.support.v4.widget.ViewDragHelper.Callback
        public void onViewReleased(View child, float xvel, float yvel) {
            int targetLeft;
            int childWidth = child.getWidth();
            boolean dismiss = false;
            if (shouldDismiss(child, xvel)) {
                targetLeft = child.getLeft() < this.mOriginalCapturedViewLeft ? this.mOriginalCapturedViewLeft - childWidth : this.mOriginalCapturedViewLeft + childWidth;
                dismiss = true;
            } else {
                targetLeft = this.mOriginalCapturedViewLeft;
            }
            if (SwipeDismissBehavior.this.mViewDragHelper.settleCapturedViewAt(targetLeft, child.getTop())) {
                ViewCompat.postOnAnimation(child, new SettleRunnable(child, dismiss));
            } else if (dismiss && SwipeDismissBehavior.this.mListener != null) {
                SwipeDismissBehavior.this.mListener.onDismiss(child);
            }
        }

        private boolean shouldDismiss(View child, float xvel) {
            if (xvel != 0.0f) {
                boolean isRtl = ViewCompat.getLayoutDirection(child) == 1;
                if (SwipeDismissBehavior.this.mSwipeDirection == 2) {
                    return true;
                }
                if (SwipeDismissBehavior.this.mSwipeDirection == 0) {
                    return isRtl ? xvel < 0.0f : xvel > 0.0f;
                } else if (SwipeDismissBehavior.this.mSwipeDirection == 1) {
                    return isRtl ? xvel > 0.0f : xvel < 0.0f;
                } else {
                    return false;
                }
            }
            int distance = child.getLeft() - this.mOriginalCapturedViewLeft;
            int thresholdDistance = Math.round(child.getWidth() * SwipeDismissBehavior.this.mDragDismissThreshold);
            return Math.abs(distance) >= thresholdDistance;
        }

        @Override // android.support.v4.widget.ViewDragHelper.Callback
        public int getViewHorizontalDragRange(View child) {
            return child.getWidth();
        }

        @Override // android.support.v4.widget.ViewDragHelper.Callback
        public int clampViewPositionHorizontal(View child, int left, int dx) {
            int min;
            int max;
            boolean isRtl = ViewCompat.getLayoutDirection(child) == 1;
            if (SwipeDismissBehavior.this.mSwipeDirection != 0) {
                if (SwipeDismissBehavior.this.mSwipeDirection == 1) {
                    if (isRtl) {
                        min = this.mOriginalCapturedViewLeft;
                        max = this.mOriginalCapturedViewLeft + child.getWidth();
                    } else {
                        min = this.mOriginalCapturedViewLeft - child.getWidth();
                        max = this.mOriginalCapturedViewLeft;
                    }
                } else {
                    min = this.mOriginalCapturedViewLeft - child.getWidth();
                    max = this.mOriginalCapturedViewLeft + child.getWidth();
                }
            } else if (isRtl) {
                min = this.mOriginalCapturedViewLeft - child.getWidth();
                max = this.mOriginalCapturedViewLeft;
            } else {
                min = this.mOriginalCapturedViewLeft;
                max = this.mOriginalCapturedViewLeft + child.getWidth();
            }
            return SwipeDismissBehavior.clamp(min, left, max);
        }

        @Override // android.support.v4.widget.ViewDragHelper.Callback
        public int clampViewPositionVertical(View child, int top, int dy) {
            return child.getTop();
        }

        @Override // android.support.v4.widget.ViewDragHelper.Callback
        public void onViewPositionChanged(View child, int left, int top, int dx, int dy) {
            float startAlphaDistance = this.mOriginalCapturedViewLeft + (child.getWidth() * SwipeDismissBehavior.this.mAlphaStartSwipeDistance);
            float endAlphaDistance = this.mOriginalCapturedViewLeft + (child.getWidth() * SwipeDismissBehavior.this.mAlphaEndSwipeDistance);
            if (left <= startAlphaDistance) {
                ViewCompat.setAlpha(child, 1.0f);
            } else if (left >= endAlphaDistance) {
                ViewCompat.setAlpha(child, 0.0f);
            } else {
                float distance = SwipeDismissBehavior.fraction(startAlphaDistance, endAlphaDistance, left);
                ViewCompat.setAlpha(child, SwipeDismissBehavior.clamp(0.0f, 1.0f - distance, 1.0f));
            }
        }
    };

    /* loaded from: classes.dex */
    public interface OnDismissListener {
        void onDismiss(View view);

        void onDragStateChanged(int i);
    }

    public void setListener(OnDismissListener listener) {
        this.mListener = listener;
    }

    public void setSwipeDirection(int direction) {
        this.mSwipeDirection = direction;
    }

    public void setDragDismissDistance(float distance) {
        this.mDragDismissThreshold = clamp(0.0f, distance, 1.0f);
    }

    public void setStartAlphaSwipeDistance(float fraction) {
        this.mAlphaStartSwipeDistance = clamp(0.0f, fraction, 1.0f);
    }

    public void setEndAlphaSwipeDistance(float fraction) {
        this.mAlphaEndSwipeDistance = clamp(0.0f, fraction, 1.0f);
    }

    public void setSensitivity(float sensitivity) {
        this.mSensitivity = sensitivity;
        this.mSensitivitySet = true;
    }

    @Override // android.support.design.widget.CoordinatorLayout.Behavior
    public boolean onInterceptTouchEvent(CoordinatorLayout parent, V child, MotionEvent event) {
        switch (MotionEventCompat.getActionMasked(event)) {
            case 1:
            case 3:
                if (this.mIgnoreEvents) {
                    this.mIgnoreEvents = false;
                    return false;
                }
                break;
            case 2:
            default:
                this.mIgnoreEvents = !parent.isPointInChildBounds(child, (int) event.getX(), (int) event.getY());
                break;
        }
        if (this.mIgnoreEvents) {
            return false;
        }
        ensureViewDragHelper(parent);
        return this.mViewDragHelper.shouldInterceptTouchEvent(event);
    }

    @Override // android.support.design.widget.CoordinatorLayout.Behavior
    public boolean onTouchEvent(CoordinatorLayout parent, V child, MotionEvent event) {
        if (this.mViewDragHelper != null) {
            this.mViewDragHelper.processTouchEvent(event);
            return true;
        }
        return false;
    }

    private void ensureViewDragHelper(ViewGroup parent) {
        if (this.mViewDragHelper == null) {
            this.mViewDragHelper = this.mSensitivitySet ? ViewDragHelper.create(parent, this.mSensitivity, this.mDragCallback) : ViewDragHelper.create(parent, this.mDragCallback);
        }
    }

    /* loaded from: classes.dex */
    private class SettleRunnable implements Runnable {
        private final boolean mDismiss;
        private final View mView;

        SettleRunnable(View view, boolean dismiss) {
            this.mView = view;
            this.mDismiss = dismiss;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (SwipeDismissBehavior.this.mViewDragHelper != null && SwipeDismissBehavior.this.mViewDragHelper.continueSettling(true)) {
                ViewCompat.postOnAnimation(this.mView, this);
            } else if (this.mDismiss && SwipeDismissBehavior.this.mListener != null) {
                SwipeDismissBehavior.this.mListener.onDismiss(this.mView);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static float clamp(float min, float value, float max) {
        return Math.min(Math.max(min, value), max);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static int clamp(int min, int value, int max) {
        return Math.min(Math.max(min, value), max);
    }

    public int getDragState() {
        if (this.mViewDragHelper != null) {
            return this.mViewDragHelper.getViewDragState();
        }
        return 0;
    }

    static float fraction(float startValue, float endValue, float value) {
        return (value - startValue) / (endValue - startValue);
    }
}
