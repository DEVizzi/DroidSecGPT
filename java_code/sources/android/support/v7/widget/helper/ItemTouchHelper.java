package android.support.v7.widget.helper;

import android.graphics.Canvas;
import android.graphics.Rect;
import android.os.Build;
import android.support.v4.animation.AnimatorCompatHelper;
import android.support.v4.animation.AnimatorListenerCompat;
import android.support.v4.animation.AnimatorUpdateListenerCompat;
import android.support.v4.animation.ValueAnimatorCompat;
import android.support.v4.view.GestureDetectorCompat;
import android.support.v4.view.MotionEventCompat;
import android.support.v4.view.VelocityTrackerCompat;
import android.support.v4.view.ViewCompat;
import android.support.v7.recyclerview.R;
import android.support.v7.widget.RecyclerView;
import android.support.v7.widget.helper.ItemTouchUIUtilImpl;
import android.util.Log;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewParent;
import android.view.animation.Interpolator;
import java.util.ArrayList;
import java.util.List;
/* loaded from: classes.dex */
public class ItemTouchHelper extends RecyclerView.ItemDecoration implements RecyclerView.OnChildAttachStateChangeListener {
    private static final int ACTION_MODE_DRAG_MASK = 16711680;
    private static final int ACTION_MODE_IDLE_MASK = 255;
    private static final int ACTION_MODE_SWIPE_MASK = 65280;
    public static final int ACTION_STATE_DRAG = 2;
    public static final int ACTION_STATE_IDLE = 0;
    public static final int ACTION_STATE_SWIPE = 1;
    private static final int ACTIVE_POINTER_ID_NONE = -1;
    public static final int ANIMATION_TYPE_DRAG = 8;
    public static final int ANIMATION_TYPE_SWIPE_CANCEL = 4;
    public static final int ANIMATION_TYPE_SWIPE_SUCCESS = 2;
    private static final boolean DEBUG = false;
    private static final int DIRECTION_FLAG_COUNT = 8;
    public static final int DOWN = 2;
    public static final int END = 32;
    public static final int LEFT = 4;
    public static final int RIGHT = 8;
    public static final int START = 16;
    private static final String TAG = "ItemTouchHelper";
    public static final int UP = 1;
    Callback mCallback;
    private List<Integer> mDistances;
    private long mDragScrollStartTimeInMs;
    float mDx;
    float mDy;
    private GestureDetectorCompat mGestureDetector;
    float mInitialTouchX;
    float mInitialTouchY;
    private RecyclerView mRecyclerView;
    int mSelectedFlags;
    float mSelectedStartX;
    float mSelectedStartY;
    private int mSlop;
    private List<RecyclerView.ViewHolder> mSwapTargets;
    private Rect mTmpRect;
    private VelocityTracker mVelocityTracker;
    final List<View> mPendingCleanup = new ArrayList();
    private final float[] mTmpPosition = new float[2];
    RecyclerView.ViewHolder mSelected = null;
    int mActivePointerId = -1;
    int mActionState = 0;
    List<RecoverAnimation> mRecoverAnimations = new ArrayList();
    private final Runnable mScrollRunnable = new Runnable() { // from class: android.support.v7.widget.helper.ItemTouchHelper.1
        @Override // java.lang.Runnable
        public void run() {
            if (ItemTouchHelper.this.mSelected != null && ItemTouchHelper.this.scrollIfNecessary()) {
                if (ItemTouchHelper.this.mSelected != null) {
                    ItemTouchHelper.this.moveIfNecessary(ItemTouchHelper.this.mSelected);
                }
                ItemTouchHelper.this.mRecyclerView.removeCallbacks(ItemTouchHelper.this.mScrollRunnable);
                ViewCompat.postOnAnimation(ItemTouchHelper.this.mRecyclerView, this);
            }
        }
    };
    private RecyclerView.ChildDrawingOrderCallback mChildDrawingOrderCallback = null;
    private View mOverdrawChild = null;
    private int mOverdrawChildPosition = -1;
    private final RecyclerView.OnItemTouchListener mOnItemTouchListener = new RecyclerView.OnItemTouchListener() { // from class: android.support.v7.widget.helper.ItemTouchHelper.2
        @Override // android.support.v7.widget.RecyclerView.OnItemTouchListener
        public boolean onInterceptTouchEvent(RecyclerView recyclerView, MotionEvent event) {
            int index;
            RecoverAnimation animation;
            ItemTouchHelper.this.mGestureDetector.onTouchEvent(event);
            int action = MotionEventCompat.getActionMasked(event);
            if (action == 0) {
                ItemTouchHelper.this.mActivePointerId = MotionEventCompat.getPointerId(event, 0);
                ItemTouchHelper.this.mInitialTouchX = event.getX();
                ItemTouchHelper.this.mInitialTouchY = event.getY();
                ItemTouchHelper.this.obtainVelocityTracker();
                if (ItemTouchHelper.this.mSelected == null && (animation = ItemTouchHelper.this.findAnimation(event)) != null) {
                    ItemTouchHelper.this.mInitialTouchX -= animation.mX;
                    ItemTouchHelper.this.mInitialTouchY -= animation.mY;
                    ItemTouchHelper.this.endRecoverAnimation(animation.mViewHolder, true);
                    if (ItemTouchHelper.this.mPendingCleanup.remove(animation.mViewHolder.itemView)) {
                        ItemTouchHelper.this.mCallback.clearView(ItemTouchHelper.this.mRecyclerView, animation.mViewHolder);
                    }
                    ItemTouchHelper.this.select(animation.mViewHolder, animation.mActionState);
                    ItemTouchHelper.this.updateDxDy(event, ItemTouchHelper.this.mSelectedFlags, 0);
                }
            } else if (action == 3 || action == 1) {
                ItemTouchHelper.this.mActivePointerId = -1;
                ItemTouchHelper.this.select(null, 0);
            } else if (ItemTouchHelper.this.mActivePointerId != -1 && (index = MotionEventCompat.findPointerIndex(event, ItemTouchHelper.this.mActivePointerId)) >= 0) {
                ItemTouchHelper.this.checkSelectForSwipe(action, event, index);
            }
            if (ItemTouchHelper.this.mVelocityTracker != null) {
                ItemTouchHelper.this.mVelocityTracker.addMovement(event);
            }
            return ItemTouchHelper.this.mSelected != null;
        }

        @Override // android.support.v7.widget.RecyclerView.OnItemTouchListener
        public void onTouchEvent(RecyclerView recyclerView, MotionEvent event) {
            ItemTouchHelper.this.mGestureDetector.onTouchEvent(event);
            if (ItemTouchHelper.this.mVelocityTracker != null) {
                ItemTouchHelper.this.mVelocityTracker.addMovement(event);
            }
            if (ItemTouchHelper.this.mActivePointerId != -1) {
                int action = MotionEventCompat.getActionMasked(event);
                int activePointerIndex = MotionEventCompat.findPointerIndex(event, ItemTouchHelper.this.mActivePointerId);
                if (activePointerIndex >= 0) {
                    ItemTouchHelper.this.checkSelectForSwipe(action, event, activePointerIndex);
                }
                RecyclerView.ViewHolder viewHolder = ItemTouchHelper.this.mSelected;
                if (viewHolder != null) {
                    switch (action) {
                        case 1:
                        case 3:
                            if (ItemTouchHelper.this.mVelocityTracker != null) {
                                ItemTouchHelper.this.mVelocityTracker.computeCurrentVelocity(1000, ItemTouchHelper.this.mRecyclerView.getMaxFlingVelocity());
                            }
                            ItemTouchHelper.this.select(null, 0);
                            ItemTouchHelper.this.mActivePointerId = -1;
                            return;
                        case 2:
                            if (activePointerIndex >= 0) {
                                ItemTouchHelper.this.updateDxDy(event, ItemTouchHelper.this.mSelectedFlags, activePointerIndex);
                                ItemTouchHelper.this.moveIfNecessary(viewHolder);
                                ItemTouchHelper.this.mRecyclerView.removeCallbacks(ItemTouchHelper.this.mScrollRunnable);
                                ItemTouchHelper.this.mScrollRunnable.run();
                                ItemTouchHelper.this.mRecyclerView.invalidate();
                                return;
                            }
                            return;
                        case 4:
                        case 5:
                        default:
                            return;
                        case 6:
                            int pointerIndex = MotionEventCompat.getActionIndex(event);
                            int pointerId = MotionEventCompat.getPointerId(event, pointerIndex);
                            if (pointerId == ItemTouchHelper.this.mActivePointerId) {
                                if (ItemTouchHelper.this.mVelocityTracker != null) {
                                    ItemTouchHelper.this.mVelocityTracker.computeCurrentVelocity(1000, ItemTouchHelper.this.mRecyclerView.getMaxFlingVelocity());
                                }
                                int newPointerIndex = pointerIndex == 0 ? 1 : 0;
                                ItemTouchHelper.this.mActivePointerId = MotionEventCompat.getPointerId(event, newPointerIndex);
                                ItemTouchHelper.this.updateDxDy(event, ItemTouchHelper.this.mSelectedFlags, pointerIndex);
                                return;
                            }
                            return;
                    }
                }
            }
        }

        @Override // android.support.v7.widget.RecyclerView.OnItemTouchListener
        public void onRequestDisallowInterceptTouchEvent(boolean disallowIntercept) {
            if (disallowIntercept) {
                ItemTouchHelper.this.select(null, 0);
            }
        }
    };

    /* loaded from: classes.dex */
    public interface ViewDropHandler {
        void prepareForDrop(View view, View view2, int i, int i2);
    }

    public ItemTouchHelper(Callback callback) {
        this.mCallback = callback;
    }

    private static boolean hitTest(View child, float x, float y, float left, float top) {
        return x >= left && x <= ((float) child.getWidth()) + left && y >= top && y <= ((float) child.getHeight()) + top;
    }

    public void attachToRecyclerView(RecyclerView recyclerView) {
        if (this.mRecyclerView != recyclerView) {
            if (this.mRecyclerView != null) {
                destroyCallbacks();
            }
            this.mRecyclerView = recyclerView;
            if (this.mRecyclerView != null) {
                setupCallbacks();
            }
        }
    }

    private void setupCallbacks() {
        ViewConfiguration vc = ViewConfiguration.get(this.mRecyclerView.getContext());
        this.mSlop = vc.getScaledTouchSlop();
        this.mRecyclerView.addItemDecoration(this);
        this.mRecyclerView.addOnItemTouchListener(this.mOnItemTouchListener);
        this.mRecyclerView.addOnChildAttachStateChangeListener(this);
        initGestureDetector();
    }

    private void destroyCallbacks() {
        this.mRecyclerView.removeItemDecoration(this);
        this.mRecyclerView.removeOnItemTouchListener(this.mOnItemTouchListener);
        this.mRecyclerView.removeOnChildAttachStateChangeListener(this);
        int recoverAnimSize = this.mRecoverAnimations.size();
        for (int i = recoverAnimSize - 1; i >= 0; i--) {
            RecoverAnimation recoverAnimation = this.mRecoverAnimations.get(0);
            this.mCallback.clearView(this.mRecyclerView, recoverAnimation.mViewHolder);
        }
        this.mRecoverAnimations.clear();
        this.mOverdrawChild = null;
        this.mOverdrawChildPosition = -1;
        releaseVelocityTracker();
    }

    private void initGestureDetector() {
        if (this.mGestureDetector == null) {
            this.mGestureDetector = new GestureDetectorCompat(this.mRecyclerView.getContext(), new ItemTouchHelperGestureListener());
        }
    }

    private void getSelectedDxDy(float[] outPosition) {
        if ((this.mSelectedFlags & 12) != 0) {
            outPosition[0] = (this.mSelectedStartX + this.mDx) - this.mSelected.itemView.getLeft();
        } else {
            outPosition[0] = ViewCompat.getTranslationX(this.mSelected.itemView);
        }
        if ((this.mSelectedFlags & 3) != 0) {
            outPosition[1] = (this.mSelectedStartY + this.mDy) - this.mSelected.itemView.getTop();
        } else {
            outPosition[1] = ViewCompat.getTranslationY(this.mSelected.itemView);
        }
    }

    @Override // android.support.v7.widget.RecyclerView.ItemDecoration
    public void onDrawOver(Canvas c, RecyclerView parent, RecyclerView.State state) {
        float dx = 0.0f;
        float dy = 0.0f;
        if (this.mSelected != null) {
            getSelectedDxDy(this.mTmpPosition);
            dx = this.mTmpPosition[0];
            dy = this.mTmpPosition[1];
        }
        this.mCallback.onDrawOver(c, parent, this.mSelected, this.mRecoverAnimations, this.mActionState, dx, dy);
    }

    @Override // android.support.v7.widget.RecyclerView.ItemDecoration
    public void onDraw(Canvas c, RecyclerView parent, RecyclerView.State state) {
        this.mOverdrawChildPosition = -1;
        float dx = 0.0f;
        float dy = 0.0f;
        if (this.mSelected != null) {
            getSelectedDxDy(this.mTmpPosition);
            dx = this.mTmpPosition[0];
            dy = this.mTmpPosition[1];
        }
        this.mCallback.onDraw(c, parent, this.mSelected, this.mRecoverAnimations, this.mActionState, dx, dy);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void select(RecyclerView.ViewHolder selected, int actionState) {
        float targetTranslateX;
        float targetTranslateY;
        int animationType;
        if (selected != this.mSelected || actionState != this.mActionState) {
            this.mDragScrollStartTimeInMs = Long.MIN_VALUE;
            int prevActionState = this.mActionState;
            endRecoverAnimation(selected, true);
            this.mActionState = actionState;
            if (actionState == 2) {
                this.mOverdrawChild = selected.itemView;
                addChildDrawingOrderCallback();
            }
            int actionStateMask = (1 << ((actionState * 8) + 8)) - 1;
            boolean preventLayout = false;
            if (this.mSelected != null) {
                final RecyclerView.ViewHolder prevSelected = this.mSelected;
                if (prevSelected.itemView.getParent() != null) {
                    final int swipeDir = prevActionState == 2 ? 0 : swipeIfNecessary(prevSelected);
                    releaseVelocityTracker();
                    switch (swipeDir) {
                        case 1:
                        case 2:
                            targetTranslateX = 0.0f;
                            targetTranslateY = Math.signum(this.mDy) * this.mRecyclerView.getHeight();
                            break;
                        case 4:
                        case 8:
                        case 16:
                        case 32:
                            targetTranslateY = 0.0f;
                            targetTranslateX = Math.signum(this.mDx) * this.mRecyclerView.getWidth();
                            break;
                        default:
                            targetTranslateX = 0.0f;
                            targetTranslateY = 0.0f;
                            break;
                    }
                    if (prevActionState == 2) {
                        animationType = 8;
                    } else if (swipeDir > 0) {
                        animationType = 2;
                    } else {
                        animationType = 4;
                    }
                    getSelectedDxDy(this.mTmpPosition);
                    float currentTranslateX = this.mTmpPosition[0];
                    float currentTranslateY = this.mTmpPosition[1];
                    RecoverAnimation rv = new RecoverAnimation(prevSelected, animationType, prevActionState, currentTranslateX, currentTranslateY, targetTranslateX, targetTranslateY) { // from class: android.support.v7.widget.helper.ItemTouchHelper.3
                        @Override // android.support.v7.widget.helper.ItemTouchHelper.RecoverAnimation, android.support.v4.animation.AnimatorListenerCompat
                        public void onAnimationEnd(ValueAnimatorCompat animation) {
                            super.onAnimationEnd(animation);
                            if (!this.mOverridden) {
                                if (swipeDir <= 0) {
                                    ItemTouchHelper.this.mCallback.clearView(ItemTouchHelper.this.mRecyclerView, prevSelected);
                                } else {
                                    ItemTouchHelper.this.mPendingCleanup.add(prevSelected.itemView);
                                    this.mIsPendingCleanup = true;
                                    if (swipeDir > 0) {
                                        ItemTouchHelper.this.postDispatchSwipe(this, swipeDir);
                                    }
                                }
                                if (ItemTouchHelper.this.mOverdrawChild == prevSelected.itemView) {
                                    ItemTouchHelper.this.removeChildDrawingOrderCallbackIfNecessary(prevSelected.itemView);
                                }
                            }
                        }
                    };
                    long duration = this.mCallback.getAnimationDuration(this.mRecyclerView, animationType, targetTranslateX - currentTranslateX, targetTranslateY - currentTranslateY);
                    rv.setDuration(duration);
                    this.mRecoverAnimations.add(rv);
                    rv.start();
                    preventLayout = true;
                } else {
                    removeChildDrawingOrderCallbackIfNecessary(prevSelected.itemView);
                    this.mCallback.clearView(this.mRecyclerView, prevSelected);
                }
                this.mSelected = null;
            }
            if (selected != null) {
                this.mSelectedFlags = (this.mCallback.getAbsoluteMovementFlags(this.mRecyclerView, selected) & actionStateMask) >> (this.mActionState * 8);
                this.mSelectedStartX = selected.itemView.getLeft();
                this.mSelectedStartY = selected.itemView.getTop();
                this.mSelected = selected;
                if (actionState == 2) {
                    this.mSelected.itemView.performHapticFeedback(0);
                }
            }
            ViewParent rvParent = this.mRecyclerView.getParent();
            if (rvParent != null) {
                rvParent.requestDisallowInterceptTouchEvent(this.mSelected != null);
            }
            if (!preventLayout) {
                this.mRecyclerView.getLayoutManager().requestSimpleAnimationsInNextLayout();
            }
            this.mCallback.onSelectedChanged(this.mSelected, this.mActionState);
            this.mRecyclerView.invalidate();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void postDispatchSwipe(final RecoverAnimation anim, final int swipeDir) {
        this.mRecyclerView.post(new Runnable() { // from class: android.support.v7.widget.helper.ItemTouchHelper.4
            @Override // java.lang.Runnable
            public void run() {
                if (ItemTouchHelper.this.mRecyclerView != null && ItemTouchHelper.this.mRecyclerView.isAttachedToWindow() && !anim.mOverridden && anim.mViewHolder.getAdapterPosition() != -1) {
                    RecyclerView.ItemAnimator animator = ItemTouchHelper.this.mRecyclerView.getItemAnimator();
                    if ((animator != null && animator.isRunning(null)) || ItemTouchHelper.this.hasRunningRecoverAnim()) {
                        ItemTouchHelper.this.mRecyclerView.post(this);
                    } else {
                        ItemTouchHelper.this.mCallback.onSwiped(anim.mViewHolder, swipeDir);
                    }
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean hasRunningRecoverAnim() {
        int size = this.mRecoverAnimations.size();
        for (int i = 0; i < size; i++) {
            if (!this.mRecoverAnimations.get(i).mEnded) {
                return true;
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean scrollIfNecessary() {
        int bottomDiff;
        int rightDiff;
        if (this.mSelected == null) {
            this.mDragScrollStartTimeInMs = Long.MIN_VALUE;
            return false;
        }
        long now = System.currentTimeMillis();
        long scrollDuration = this.mDragScrollStartTimeInMs == Long.MIN_VALUE ? 0L : now - this.mDragScrollStartTimeInMs;
        RecyclerView.LayoutManager lm = this.mRecyclerView.getLayoutManager();
        if (this.mTmpRect == null) {
            this.mTmpRect = new Rect();
        }
        int scrollX = 0;
        int scrollY = 0;
        lm.calculateItemDecorationsForChild(this.mSelected.itemView, this.mTmpRect);
        if (lm.canScrollHorizontally()) {
            int curX = (int) (this.mSelectedStartX + this.mDx);
            int leftDiff = (curX - this.mTmpRect.left) - this.mRecyclerView.getPaddingLeft();
            if (this.mDx < 0.0f && leftDiff < 0) {
                scrollX = leftDiff;
            } else if (this.mDx > 0.0f && (rightDiff = ((this.mSelected.itemView.getWidth() + curX) + this.mTmpRect.right) - (this.mRecyclerView.getWidth() - this.mRecyclerView.getPaddingRight())) > 0) {
                scrollX = rightDiff;
            }
        }
        if (lm.canScrollVertically()) {
            int curY = (int) (this.mSelectedStartY + this.mDy);
            int topDiff = (curY - this.mTmpRect.top) - this.mRecyclerView.getPaddingTop();
            if (this.mDy < 0.0f && topDiff < 0) {
                scrollY = topDiff;
            } else if (this.mDy > 0.0f && (bottomDiff = ((this.mSelected.itemView.getHeight() + curY) + this.mTmpRect.bottom) - (this.mRecyclerView.getHeight() - this.mRecyclerView.getPaddingBottom())) > 0) {
                scrollY = bottomDiff;
            }
        }
        if (scrollX != 0) {
            scrollX = this.mCallback.interpolateOutOfBoundsScroll(this.mRecyclerView, this.mSelected.itemView.getWidth(), scrollX, this.mRecyclerView.getWidth(), scrollDuration);
        }
        if (scrollY != 0) {
            scrollY = this.mCallback.interpolateOutOfBoundsScroll(this.mRecyclerView, this.mSelected.itemView.getHeight(), scrollY, this.mRecyclerView.getHeight(), scrollDuration);
        }
        if (scrollX != 0 || scrollY != 0) {
            if (this.mDragScrollStartTimeInMs == Long.MIN_VALUE) {
                this.mDragScrollStartTimeInMs = now;
            }
            this.mRecyclerView.scrollBy(scrollX, scrollY);
            return true;
        }
        this.mDragScrollStartTimeInMs = Long.MIN_VALUE;
        return false;
    }

    private List<RecyclerView.ViewHolder> findSwapTargets(RecyclerView.ViewHolder viewHolder) {
        if (this.mSwapTargets == null) {
            this.mSwapTargets = new ArrayList();
            this.mDistances = new ArrayList();
        } else {
            this.mSwapTargets.clear();
            this.mDistances.clear();
        }
        int margin = this.mCallback.getBoundingBoxMargin();
        int left = Math.round(this.mSelectedStartX + this.mDx) - margin;
        int top = Math.round(this.mSelectedStartY + this.mDy) - margin;
        int right = viewHolder.itemView.getWidth() + left + (margin * 2);
        int bottom = viewHolder.itemView.getHeight() + top + (margin * 2);
        int centerX = (left + right) / 2;
        int centerY = (top + bottom) / 2;
        RecyclerView.LayoutManager lm = this.mRecyclerView.getLayoutManager();
        int childCount = lm.getChildCount();
        for (int i = 0; i < childCount; i++) {
            View other = lm.getChildAt(i);
            if (other != viewHolder.itemView && other.getBottom() >= top && other.getTop() <= bottom && other.getRight() >= left && other.getLeft() <= right) {
                RecyclerView.ViewHolder otherVh = this.mRecyclerView.getChildViewHolder(other);
                if (this.mCallback.canDropOver(this.mRecyclerView, this.mSelected, otherVh)) {
                    int dx = Math.abs(centerX - ((other.getLeft() + other.getRight()) / 2));
                    int dy = Math.abs(centerY - ((other.getTop() + other.getBottom()) / 2));
                    int dist = (dx * dx) + (dy * dy);
                    int pos = 0;
                    int cnt = this.mSwapTargets.size();
                    for (int j = 0; j < cnt && dist > this.mDistances.get(j).intValue(); j++) {
                        pos++;
                    }
                    this.mSwapTargets.add(pos, otherVh);
                    this.mDistances.add(pos, Integer.valueOf(dist));
                }
            }
        }
        return this.mSwapTargets;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void moveIfNecessary(RecyclerView.ViewHolder viewHolder) {
        if (!this.mRecyclerView.isLayoutRequested() && this.mActionState == 2) {
            float threshold = this.mCallback.getMoveThreshold(viewHolder);
            int x = (int) (this.mSelectedStartX + this.mDx);
            int y = (int) (this.mSelectedStartY + this.mDy);
            if (Math.abs(y - viewHolder.itemView.getTop()) >= viewHolder.itemView.getHeight() * threshold || Math.abs(x - viewHolder.itemView.getLeft()) >= viewHolder.itemView.getWidth() * threshold) {
                List<RecyclerView.ViewHolder> swapTargets = findSwapTargets(viewHolder);
                if (swapTargets.size() != 0) {
                    RecyclerView.ViewHolder target = this.mCallback.chooseDropTarget(viewHolder, swapTargets, x, y);
                    if (target == null) {
                        this.mSwapTargets.clear();
                        this.mDistances.clear();
                        return;
                    }
                    int toPosition = target.getAdapterPosition();
                    int fromPosition = viewHolder.getAdapterPosition();
                    if (this.mCallback.onMove(this.mRecyclerView, viewHolder, target)) {
                        this.mCallback.onMoved(this.mRecyclerView, viewHolder, fromPosition, target, toPosition, x, y);
                    }
                }
            }
        }
    }

    @Override // android.support.v7.widget.RecyclerView.OnChildAttachStateChangeListener
    public void onChildViewAttachedToWindow(View view) {
    }

    @Override // android.support.v7.widget.RecyclerView.OnChildAttachStateChangeListener
    public void onChildViewDetachedFromWindow(View view) {
        removeChildDrawingOrderCallbackIfNecessary(view);
        RecyclerView.ViewHolder holder = this.mRecyclerView.getChildViewHolder(view);
        if (holder != null) {
            if (this.mSelected != null && holder == this.mSelected) {
                select(null, 0);
                return;
            }
            endRecoverAnimation(holder, false);
            if (this.mPendingCleanup.remove(holder.itemView)) {
                this.mCallback.clearView(this.mRecyclerView, holder);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int endRecoverAnimation(RecyclerView.ViewHolder viewHolder, boolean override) {
        int recoverAnimSize = this.mRecoverAnimations.size();
        for (int i = recoverAnimSize - 1; i >= 0; i--) {
            RecoverAnimation anim = this.mRecoverAnimations.get(i);
            if (anim.mViewHolder == viewHolder) {
                anim.mOverridden |= override;
                if (!anim.mEnded) {
                    anim.cancel();
                }
                this.mRecoverAnimations.remove(i);
                anim.mViewHolder.setIsRecyclable(true);
                return anim.mAnimationType;
            }
        }
        return 0;
    }

    @Override // android.support.v7.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(Rect outRect, View view, RecyclerView parent, RecyclerView.State state) {
        outRect.setEmpty();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void obtainVelocityTracker() {
        if (this.mVelocityTracker != null) {
            this.mVelocityTracker.recycle();
        }
        this.mVelocityTracker = VelocityTracker.obtain();
    }

    private void releaseVelocityTracker() {
        if (this.mVelocityTracker != null) {
            this.mVelocityTracker.recycle();
            this.mVelocityTracker = null;
        }
    }

    private RecyclerView.ViewHolder findSwipedView(MotionEvent motionEvent) {
        View child;
        RecyclerView.LayoutManager lm = this.mRecyclerView.getLayoutManager();
        if (this.mActivePointerId == -1) {
            return null;
        }
        int pointerIndex = MotionEventCompat.findPointerIndex(motionEvent, this.mActivePointerId);
        float dx = MotionEventCompat.getX(motionEvent, pointerIndex) - this.mInitialTouchX;
        float dy = MotionEventCompat.getY(motionEvent, pointerIndex) - this.mInitialTouchY;
        float absDx = Math.abs(dx);
        float absDy = Math.abs(dy);
        if (absDx >= this.mSlop || absDy >= this.mSlop) {
            if (absDx <= absDy || !lm.canScrollHorizontally()) {
                if ((absDy <= absDx || !lm.canScrollVertically()) && (child = findChildView(motionEvent)) != null) {
                    return this.mRecyclerView.getChildViewHolder(child);
                }
                return null;
            }
            return null;
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean checkSelectForSwipe(int action, MotionEvent motionEvent, int pointerIndex) {
        RecyclerView.ViewHolder vh;
        if (this.mSelected != null || action != 2 || this.mActionState == 2 || !this.mCallback.isItemViewSwipeEnabled() || this.mRecyclerView.getScrollState() == 1 || (vh = findSwipedView(motionEvent)) == null) {
            return false;
        }
        int movementFlags = this.mCallback.getAbsoluteMovementFlags(this.mRecyclerView, vh);
        int swipeFlags = (65280 & movementFlags) >> 8;
        if (swipeFlags == 0) {
            return false;
        }
        float x = MotionEventCompat.getX(motionEvent, pointerIndex);
        float y = MotionEventCompat.getY(motionEvent, pointerIndex);
        float dx = x - this.mInitialTouchX;
        float dy = y - this.mInitialTouchY;
        float absDx = Math.abs(dx);
        float absDy = Math.abs(dy);
        if (absDx < this.mSlop && absDy < this.mSlop) {
            return false;
        }
        if (absDx > absDy) {
            if (dx < 0.0f && (swipeFlags & 4) == 0) {
                return false;
            }
            if (dx > 0.0f && (swipeFlags & 8) == 0) {
                return false;
            }
        } else if (dy < 0.0f && (swipeFlags & 1) == 0) {
            return false;
        } else {
            if (dy > 0.0f && (swipeFlags & 2) == 0) {
                return false;
            }
        }
        this.mDy = 0.0f;
        this.mDx = 0.0f;
        this.mActivePointerId = MotionEventCompat.getPointerId(motionEvent, 0);
        select(vh, 1);
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public View findChildView(MotionEvent event) {
        float x = event.getX();
        float y = event.getY();
        if (this.mSelected != null) {
            View selectedView = this.mSelected.itemView;
            if (hitTest(selectedView, x, y, this.mSelectedStartX + this.mDx, this.mSelectedStartY + this.mDy)) {
                return selectedView;
            }
        }
        for (int i = this.mRecoverAnimations.size() - 1; i >= 0; i--) {
            RecoverAnimation anim = this.mRecoverAnimations.get(i);
            View view = anim.mViewHolder.itemView;
            if (hitTest(view, x, y, anim.mX, anim.mY)) {
                return view;
            }
        }
        return this.mRecyclerView.findChildViewUnder(x, y);
    }

    public void startDrag(RecyclerView.ViewHolder viewHolder) {
        if (!this.mCallback.hasDragFlag(this.mRecyclerView, viewHolder)) {
            Log.e(TAG, "Start drag has been called but swiping is not enabled");
        } else if (viewHolder.itemView.getParent() != this.mRecyclerView) {
            Log.e(TAG, "Start drag has been called with a view holder which is not a child of the RecyclerView which is controlled by this ItemTouchHelper.");
        } else {
            obtainVelocityTracker();
            this.mDy = 0.0f;
            this.mDx = 0.0f;
            select(viewHolder, 2);
        }
    }

    public void startSwipe(RecyclerView.ViewHolder viewHolder) {
        if (!this.mCallback.hasSwipeFlag(this.mRecyclerView, viewHolder)) {
            Log.e(TAG, "Start swipe has been called but dragging is not enabled");
        } else if (viewHolder.itemView.getParent() != this.mRecyclerView) {
            Log.e(TAG, "Start swipe has been called with a view holder which is not a child of the RecyclerView controlled by this ItemTouchHelper.");
        } else {
            obtainVelocityTracker();
            this.mDy = 0.0f;
            this.mDx = 0.0f;
            select(viewHolder, 1);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public RecoverAnimation findAnimation(MotionEvent event) {
        if (this.mRecoverAnimations.isEmpty()) {
            return null;
        }
        View target = findChildView(event);
        for (int i = this.mRecoverAnimations.size() - 1; i >= 0; i--) {
            RecoverAnimation anim = this.mRecoverAnimations.get(i);
            if (anim.mViewHolder.itemView == target) {
                return anim;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateDxDy(MotionEvent ev, int directionFlags, int pointerIndex) {
        float x = MotionEventCompat.getX(ev, pointerIndex);
        float y = MotionEventCompat.getY(ev, pointerIndex);
        this.mDx = x - this.mInitialTouchX;
        this.mDy = y - this.mInitialTouchY;
        if ((directionFlags & 4) == 0) {
            this.mDx = Math.max(0.0f, this.mDx);
        }
        if ((directionFlags & 8) == 0) {
            this.mDx = Math.min(0.0f, this.mDx);
        }
        if ((directionFlags & 1) == 0) {
            this.mDy = Math.max(0.0f, this.mDy);
        }
        if ((directionFlags & 2) == 0) {
            this.mDy = Math.min(0.0f, this.mDy);
        }
    }

    private int swipeIfNecessary(RecyclerView.ViewHolder viewHolder) {
        if (this.mActionState == 2) {
            return 0;
        }
        int originalMovementFlags = this.mCallback.getMovementFlags(this.mRecyclerView, viewHolder);
        int absoluteMovementFlags = this.mCallback.convertToAbsoluteDirection(originalMovementFlags, ViewCompat.getLayoutDirection(this.mRecyclerView));
        int flags = (absoluteMovementFlags & 65280) >> 8;
        if (flags == 0) {
            return 0;
        }
        int originalFlags = (originalMovementFlags & 65280) >> 8;
        if (Math.abs(this.mDx) > Math.abs(this.mDy)) {
            int swipeDir = checkHorizontalSwipe(viewHolder, flags);
            if (swipeDir > 0) {
                if ((originalFlags & swipeDir) == 0) {
                    return Callback.convertToRelativeDirection(swipeDir, ViewCompat.getLayoutDirection(this.mRecyclerView));
                }
                return swipeDir;
            }
            int swipeDir2 = checkVerticalSwipe(viewHolder, flags);
            if (swipeDir2 > 0) {
                return swipeDir2;
            }
        } else {
            int swipeDir3 = checkVerticalSwipe(viewHolder, flags);
            if (swipeDir3 <= 0) {
                int swipeDir4 = checkHorizontalSwipe(viewHolder, flags);
                if (swipeDir4 > 0) {
                    if ((originalFlags & swipeDir4) == 0) {
                        return Callback.convertToRelativeDirection(swipeDir4, ViewCompat.getLayoutDirection(this.mRecyclerView));
                    }
                    return swipeDir4;
                }
            } else {
                return swipeDir3;
            }
        }
        return 0;
    }

    private int checkHorizontalSwipe(RecyclerView.ViewHolder viewHolder, int flags) {
        if ((flags & 12) != 0) {
            int dirFlag = this.mDx > 0.0f ? 8 : 4;
            if (this.mVelocityTracker != null && this.mActivePointerId > -1) {
                float xVelocity = VelocityTrackerCompat.getXVelocity(this.mVelocityTracker, this.mActivePointerId);
                int velDirFlag = xVelocity > 0.0f ? 8 : 4;
                if ((velDirFlag & flags) != 0 && dirFlag == velDirFlag && Math.abs(xVelocity) >= this.mRecyclerView.getMinFlingVelocity()) {
                    return velDirFlag;
                }
            }
            float threshold = this.mRecyclerView.getWidth() * this.mCallback.getSwipeThreshold(viewHolder);
            if ((flags & dirFlag) != 0 && Math.abs(this.mDx) > threshold) {
                return dirFlag;
            }
        }
        return 0;
    }

    private int checkVerticalSwipe(RecyclerView.ViewHolder viewHolder, int flags) {
        if ((flags & 3) != 0) {
            int dirFlag = this.mDy > 0.0f ? 2 : 1;
            if (this.mVelocityTracker != null && this.mActivePointerId > -1) {
                float yVelocity = VelocityTrackerCompat.getYVelocity(this.mVelocityTracker, this.mActivePointerId);
                int velDirFlag = yVelocity > 0.0f ? 2 : 1;
                if ((velDirFlag & flags) != 0 && velDirFlag == dirFlag && Math.abs(yVelocity) >= this.mRecyclerView.getMinFlingVelocity()) {
                    return velDirFlag;
                }
            }
            float threshold = this.mRecyclerView.getHeight() * this.mCallback.getSwipeThreshold(viewHolder);
            if ((flags & dirFlag) != 0 && Math.abs(this.mDy) > threshold) {
                return dirFlag;
            }
        }
        return 0;
    }

    private void addChildDrawingOrderCallback() {
        if (Build.VERSION.SDK_INT < 21) {
            if (this.mChildDrawingOrderCallback == null) {
                this.mChildDrawingOrderCallback = new RecyclerView.ChildDrawingOrderCallback() { // from class: android.support.v7.widget.helper.ItemTouchHelper.5
                    @Override // android.support.v7.widget.RecyclerView.ChildDrawingOrderCallback
                    public int onGetChildDrawingOrder(int childCount, int i) {
                        if (ItemTouchHelper.this.mOverdrawChild != null) {
                            int childPosition = ItemTouchHelper.this.mOverdrawChildPosition;
                            if (childPosition == -1) {
                                childPosition = ItemTouchHelper.this.mRecyclerView.indexOfChild(ItemTouchHelper.this.mOverdrawChild);
                                ItemTouchHelper.this.mOverdrawChildPosition = childPosition;
                            }
                            return i == childCount + (-1) ? childPosition : i >= childPosition ? i + 1 : i;
                        }
                        return i;
                    }
                };
            }
            this.mRecyclerView.setChildDrawingOrderCallback(this.mChildDrawingOrderCallback);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void removeChildDrawingOrderCallbackIfNecessary(View view) {
        if (view == this.mOverdrawChild) {
            this.mOverdrawChild = null;
            if (this.mChildDrawingOrderCallback != null) {
                this.mRecyclerView.setChildDrawingOrderCallback(null);
            }
        }
    }

    /* loaded from: classes.dex */
    public static abstract class Callback {
        private static final int ABS_HORIZONTAL_DIR_FLAGS = 789516;
        public static final int DEFAULT_DRAG_ANIMATION_DURATION = 200;
        public static final int DEFAULT_SWIPE_ANIMATION_DURATION = 250;
        private static final long DRAG_SCROLL_ACCELERATION_LIMIT_TIME_MS = 2000;
        static final int RELATIVE_DIR_FLAGS = 3158064;
        private static final Interpolator sDragScrollInterpolator = new Interpolator() { // from class: android.support.v7.widget.helper.ItemTouchHelper.Callback.1
            @Override // android.animation.TimeInterpolator
            public float getInterpolation(float t) {
                return t * t * t * t * t;
            }
        };
        private static final Interpolator sDragViewScrollCapInterpolator = new Interpolator() { // from class: android.support.v7.widget.helper.ItemTouchHelper.Callback.2
            @Override // android.animation.TimeInterpolator
            public float getInterpolation(float t) {
                float t2 = t - 1.0f;
                return (t2 * t2 * t2 * t2 * t2) + 1.0f;
            }
        };
        private static final ItemTouchUIUtil sUICallback;
        private int mCachedMaxScrollSpeed = -1;

        public abstract int getMovementFlags(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder);

        public abstract boolean onMove(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder, RecyclerView.ViewHolder viewHolder2);

        public abstract void onSwiped(RecyclerView.ViewHolder viewHolder, int i);

        static {
            if (Build.VERSION.SDK_INT >= 21) {
                sUICallback = new ItemTouchUIUtilImpl.Lollipop();
            } else if (Build.VERSION.SDK_INT >= 11) {
                sUICallback = new ItemTouchUIUtilImpl.Honeycomb();
            } else {
                sUICallback = new ItemTouchUIUtilImpl.Gingerbread();
            }
        }

        public static ItemTouchUIUtil getDefaultUIUtil() {
            return sUICallback;
        }

        public static int convertToRelativeDirection(int flags, int layoutDirection) {
            int masked = flags & ABS_HORIZONTAL_DIR_FLAGS;
            if (masked != 0) {
                int flags2 = flags & (masked ^ (-1));
                if (layoutDirection == 0) {
                    return flags2 | (masked << 2);
                }
                return flags2 | ((masked << 1) & (-789517)) | (((masked << 1) & ABS_HORIZONTAL_DIR_FLAGS) << 2);
            }
            return flags;
        }

        public static int makeMovementFlags(int dragFlags, int swipeFlags) {
            return makeFlag(0, swipeFlags | dragFlags) | makeFlag(1, swipeFlags) | makeFlag(2, dragFlags);
        }

        public static int makeFlag(int actionState, int directions) {
            return directions << (actionState * 8);
        }

        public int convertToAbsoluteDirection(int flags, int layoutDirection) {
            int masked = flags & RELATIVE_DIR_FLAGS;
            if (masked == 0) {
                return flags;
            }
            int flags2 = flags & (masked ^ (-1));
            if (layoutDirection == 0) {
                return flags2 | (masked >> 2);
            }
            return flags2 | ((masked >> 1) & (-3158065)) | (((masked >> 1) & RELATIVE_DIR_FLAGS) >> 2);
        }

        final int getAbsoluteMovementFlags(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder) {
            int flags = getMovementFlags(recyclerView, viewHolder);
            return convertToAbsoluteDirection(flags, ViewCompat.getLayoutDirection(recyclerView));
        }

        /* JADX INFO: Access modifiers changed from: private */
        public boolean hasDragFlag(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder) {
            int flags = getAbsoluteMovementFlags(recyclerView, viewHolder);
            return (ItemTouchHelper.ACTION_MODE_DRAG_MASK & flags) != 0;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public boolean hasSwipeFlag(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder) {
            int flags = getAbsoluteMovementFlags(recyclerView, viewHolder);
            return (65280 & flags) != 0;
        }

        public boolean canDropOver(RecyclerView recyclerView, RecyclerView.ViewHolder current, RecyclerView.ViewHolder target) {
            return true;
        }

        public boolean isLongPressDragEnabled() {
            return true;
        }

        public boolean isItemViewSwipeEnabled() {
            return true;
        }

        public int getBoundingBoxMargin() {
            return 0;
        }

        public float getSwipeThreshold(RecyclerView.ViewHolder viewHolder) {
            return 0.5f;
        }

        public float getMoveThreshold(RecyclerView.ViewHolder viewHolder) {
            return 0.5f;
        }

        public RecyclerView.ViewHolder chooseDropTarget(RecyclerView.ViewHolder selected, List<RecyclerView.ViewHolder> dropTargets, int curX, int curY) {
            int diff;
            int score;
            int diff2;
            int score2;
            int diff3;
            int score3;
            int diff4;
            int score4;
            int right = curX + selected.itemView.getWidth();
            int bottom = curY + selected.itemView.getHeight();
            RecyclerView.ViewHolder winner = null;
            int winnerScore = -1;
            int dx = curX - selected.itemView.getLeft();
            int dy = curY - selected.itemView.getTop();
            int targetsSize = dropTargets.size();
            for (int i = 0; i < targetsSize; i++) {
                RecyclerView.ViewHolder target = dropTargets.get(i);
                if (dx > 0 && (diff4 = target.itemView.getRight() - right) < 0 && target.itemView.getRight() > selected.itemView.getRight() && (score4 = Math.abs(diff4)) > winnerScore) {
                    winnerScore = score4;
                    winner = target;
                }
                if (dx < 0 && (diff3 = target.itemView.getLeft() - curX) > 0 && target.itemView.getLeft() < selected.itemView.getLeft() && (score3 = Math.abs(diff3)) > winnerScore) {
                    winnerScore = score3;
                    winner = target;
                }
                if (dy < 0 && (diff2 = target.itemView.getTop() - curY) > 0 && target.itemView.getTop() < selected.itemView.getTop() && (score2 = Math.abs(diff2)) > winnerScore) {
                    winnerScore = score2;
                    winner = target;
                }
                if (dy > 0 && (diff = target.itemView.getBottom() - bottom) < 0 && target.itemView.getBottom() > selected.itemView.getBottom() && (score = Math.abs(diff)) > winnerScore) {
                    winnerScore = score;
                    winner = target;
                }
            }
            return winner;
        }

        public void onSelectedChanged(RecyclerView.ViewHolder viewHolder, int actionState) {
            if (viewHolder != null) {
                sUICallback.onSelected(viewHolder.itemView);
            }
        }

        private int getMaxDragScroll(RecyclerView recyclerView) {
            if (this.mCachedMaxScrollSpeed == -1) {
                this.mCachedMaxScrollSpeed = recyclerView.getResources().getDimensionPixelSize(R.dimen.item_touch_helper_max_drag_scroll_per_frame);
            }
            return this.mCachedMaxScrollSpeed;
        }

        public void onMoved(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder, int fromPos, RecyclerView.ViewHolder target, int toPos, int x, int y) {
            RecyclerView.LayoutManager layoutManager = recyclerView.getLayoutManager();
            if (layoutManager instanceof ViewDropHandler) {
                ((ViewDropHandler) layoutManager).prepareForDrop(viewHolder.itemView, target.itemView, x, y);
                return;
            }
            if (layoutManager.canScrollHorizontally()) {
                int minLeft = layoutManager.getDecoratedLeft(target.itemView);
                if (minLeft <= recyclerView.getPaddingLeft()) {
                    recyclerView.scrollToPosition(toPos);
                }
                int maxRight = layoutManager.getDecoratedRight(target.itemView);
                if (maxRight >= recyclerView.getWidth() - recyclerView.getPaddingRight()) {
                    recyclerView.scrollToPosition(toPos);
                }
            }
            if (layoutManager.canScrollVertically()) {
                int minTop = layoutManager.getDecoratedTop(target.itemView);
                if (minTop <= recyclerView.getPaddingTop()) {
                    recyclerView.scrollToPosition(toPos);
                }
                int maxBottom = layoutManager.getDecoratedBottom(target.itemView);
                if (maxBottom >= recyclerView.getHeight() - recyclerView.getPaddingBottom()) {
                    recyclerView.scrollToPosition(toPos);
                }
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void onDraw(Canvas c, RecyclerView parent, RecyclerView.ViewHolder selected, List<RecoverAnimation> recoverAnimationList, int actionState, float dX, float dY) {
            int recoverAnimSize = recoverAnimationList.size();
            for (int i = 0; i < recoverAnimSize; i++) {
                RecoverAnimation anim = recoverAnimationList.get(i);
                anim.update();
                int count = c.save();
                onChildDraw(c, parent, anim.mViewHolder, anim.mX, anim.mY, anim.mActionState, false);
                c.restoreToCount(count);
            }
            if (selected != null) {
                int count2 = c.save();
                onChildDraw(c, parent, selected, dX, dY, actionState, true);
                c.restoreToCount(count2);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void onDrawOver(Canvas c, RecyclerView parent, RecyclerView.ViewHolder selected, List<RecoverAnimation> recoverAnimationList, int actionState, float dX, float dY) {
            int recoverAnimSize = recoverAnimationList.size();
            for (int i = 0; i < recoverAnimSize; i++) {
                RecoverAnimation anim = recoverAnimationList.get(i);
                int count = c.save();
                onChildDrawOver(c, parent, anim.mViewHolder, anim.mX, anim.mY, anim.mActionState, false);
                c.restoreToCount(count);
            }
            if (selected != null) {
                int count2 = c.save();
                onChildDrawOver(c, parent, selected, dX, dY, actionState, true);
                c.restoreToCount(count2);
            }
            boolean hasRunningAnimation = false;
            for (int i2 = recoverAnimSize - 1; i2 >= 0; i2--) {
                RecoverAnimation anim2 = recoverAnimationList.get(i2);
                if (anim2.mEnded && !anim2.mIsPendingCleanup) {
                    recoverAnimationList.remove(i2);
                    anim2.mViewHolder.setIsRecyclable(true);
                } else if (!anim2.mEnded) {
                    hasRunningAnimation = true;
                }
            }
            if (hasRunningAnimation) {
                parent.invalidate();
            }
        }

        public void clearView(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder) {
            sUICallback.clearView(viewHolder.itemView);
        }

        public void onChildDraw(Canvas c, RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder, float dX, float dY, int actionState, boolean isCurrentlyActive) {
            sUICallback.onDraw(c, recyclerView, viewHolder.itemView, dX, dY, actionState, isCurrentlyActive);
        }

        public void onChildDrawOver(Canvas c, RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder, float dX, float dY, int actionState, boolean isCurrentlyActive) {
            sUICallback.onDrawOver(c, recyclerView, viewHolder.itemView, dX, dY, actionState, isCurrentlyActive);
        }

        public long getAnimationDuration(RecyclerView recyclerView, int animationType, float animateDx, float animateDy) {
            RecyclerView.ItemAnimator itemAnimator = recyclerView.getItemAnimator();
            return itemAnimator == null ? animationType == 8 ? 200L : 250L : animationType == 8 ? itemAnimator.getMoveDuration() : itemAnimator.getRemoveDuration();
        }

        public int interpolateOutOfBoundsScroll(RecyclerView recyclerView, int viewSize, int viewSizeOutOfBounds, int totalSize, long msSinceStartScroll) {
            float timeRatio;
            int maxScroll = getMaxDragScroll(recyclerView);
            int absOutOfBounds = Math.abs(viewSizeOutOfBounds);
            int direction = (int) Math.signum(viewSizeOutOfBounds);
            float outOfBoundsRatio = Math.min(1.0f, (1.0f * absOutOfBounds) / viewSize);
            int cappedScroll = (int) (direction * maxScroll * sDragViewScrollCapInterpolator.getInterpolation(outOfBoundsRatio));
            if (msSinceStartScroll > DRAG_SCROLL_ACCELERATION_LIMIT_TIME_MS) {
                timeRatio = 1.0f;
            } else {
                timeRatio = ((float) msSinceStartScroll) / 2000.0f;
            }
            int value = (int) (cappedScroll * sDragScrollInterpolator.getInterpolation(timeRatio));
            return value == 0 ? viewSizeOutOfBounds > 0 ? 1 : -1 : value;
        }
    }

    /* loaded from: classes.dex */
    public static abstract class SimpleCallback extends Callback {
        private int mDefaultDragDirs;
        private int mDefaultSwipeDirs;

        public SimpleCallback(int dragDirs, int swipeDirs) {
            this.mDefaultSwipeDirs = swipeDirs;
            this.mDefaultDragDirs = dragDirs;
        }

        public void setDefaultSwipeDirs(int defaultSwipeDirs) {
            this.mDefaultSwipeDirs = defaultSwipeDirs;
        }

        public void setDefaultDragDirs(int defaultDragDirs) {
            this.mDefaultDragDirs = defaultDragDirs;
        }

        public int getSwipeDirs(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder) {
            return this.mDefaultSwipeDirs;
        }

        public int getDragDirs(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder) {
            return this.mDefaultDragDirs;
        }

        @Override // android.support.v7.widget.helper.ItemTouchHelper.Callback
        public int getMovementFlags(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder) {
            return makeMovementFlags(getDragDirs(recyclerView, viewHolder), getSwipeDirs(recyclerView, viewHolder));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class ItemTouchHelperGestureListener extends GestureDetector.SimpleOnGestureListener {
        private ItemTouchHelperGestureListener() {
        }

        @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
        public boolean onDown(MotionEvent e) {
            return true;
        }

        @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
        public void onLongPress(MotionEvent e) {
            RecyclerView.ViewHolder vh;
            View child = ItemTouchHelper.this.findChildView(e);
            if (child != null && (vh = ItemTouchHelper.this.mRecyclerView.getChildViewHolder(child)) != null && ItemTouchHelper.this.mCallback.hasDragFlag(ItemTouchHelper.this.mRecyclerView, vh)) {
                int pointerId = MotionEventCompat.getPointerId(e, 0);
                if (pointerId == ItemTouchHelper.this.mActivePointerId) {
                    int index = MotionEventCompat.findPointerIndex(e, ItemTouchHelper.this.mActivePointerId);
                    float x = MotionEventCompat.getX(e, index);
                    float y = MotionEventCompat.getY(e, index);
                    ItemTouchHelper.this.mInitialTouchX = x;
                    ItemTouchHelper.this.mInitialTouchY = y;
                    ItemTouchHelper itemTouchHelper = ItemTouchHelper.this;
                    ItemTouchHelper.this.mDy = 0.0f;
                    itemTouchHelper.mDx = 0.0f;
                    if (ItemTouchHelper.this.mCallback.isLongPressDragEnabled()) {
                        ItemTouchHelper.this.select(vh, 2);
                    }
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class RecoverAnimation implements AnimatorListenerCompat {
        final int mActionState;
        private final int mAnimationType;
        private float mFraction;
        public boolean mIsPendingCleanup;
        final float mStartDx;
        final float mStartDy;
        final float mTargetX;
        final float mTargetY;
        final RecyclerView.ViewHolder mViewHolder;
        float mX;
        float mY;
        boolean mOverridden = false;
        private boolean mEnded = false;
        private final ValueAnimatorCompat mValueAnimator = AnimatorCompatHelper.emptyValueAnimator();

        public RecoverAnimation(RecyclerView.ViewHolder viewHolder, int animationType, int actionState, float startDx, float startDy, float targetX, float targetY) {
            this.mActionState = actionState;
            this.mAnimationType = animationType;
            this.mViewHolder = viewHolder;
            this.mStartDx = startDx;
            this.mStartDy = startDy;
            this.mTargetX = targetX;
            this.mTargetY = targetY;
            this.mValueAnimator.addUpdateListener(new AnimatorUpdateListenerCompat() { // from class: android.support.v7.widget.helper.ItemTouchHelper.RecoverAnimation.1
                @Override // android.support.v4.animation.AnimatorUpdateListenerCompat
                public void onAnimationUpdate(ValueAnimatorCompat animation) {
                    RecoverAnimation.this.setFraction(animation.getAnimatedFraction());
                }
            });
            this.mValueAnimator.setTarget(viewHolder.itemView);
            this.mValueAnimator.addListener(this);
            setFraction(0.0f);
        }

        public void setDuration(long duration) {
            this.mValueAnimator.setDuration(duration);
        }

        public void start() {
            this.mViewHolder.setIsRecyclable(false);
            this.mValueAnimator.start();
        }

        public void cancel() {
            this.mValueAnimator.cancel();
        }

        public void setFraction(float fraction) {
            this.mFraction = fraction;
        }

        public void update() {
            if (this.mStartDx == this.mTargetX) {
                this.mX = ViewCompat.getTranslationX(this.mViewHolder.itemView);
            } else {
                this.mX = this.mStartDx + (this.mFraction * (this.mTargetX - this.mStartDx));
            }
            if (this.mStartDy == this.mTargetY) {
                this.mY = ViewCompat.getTranslationY(this.mViewHolder.itemView);
            } else {
                this.mY = this.mStartDy + (this.mFraction * (this.mTargetY - this.mStartDy));
            }
        }

        @Override // android.support.v4.animation.AnimatorListenerCompat
        public void onAnimationStart(ValueAnimatorCompat animation) {
        }

        @Override // android.support.v4.animation.AnimatorListenerCompat
        public void onAnimationEnd(ValueAnimatorCompat animation) {
            this.mEnded = true;
        }

        @Override // android.support.v4.animation.AnimatorListenerCompat
        public void onAnimationCancel(ValueAnimatorCompat animation) {
            setFraction(1.0f);
        }

        @Override // android.support.v4.animation.AnimatorListenerCompat
        public void onAnimationRepeat(ValueAnimatorCompat animation) {
        }
    }
}
