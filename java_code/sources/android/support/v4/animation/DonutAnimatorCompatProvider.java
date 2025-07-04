package android.support.v4.animation;

import android.view.View;
import java.util.ArrayList;
import java.util.List;
/* loaded from: classes.dex */
class DonutAnimatorCompatProvider implements AnimatorProvider {
    @Override // android.support.v4.animation.AnimatorProvider
    public ValueAnimatorCompat emptyValueAnimator() {
        return new DonutFloatValueAnimator();
    }

    /* loaded from: classes.dex */
    private static class DonutFloatValueAnimator implements ValueAnimatorCompat {
        private long mStartTime;
        View mTarget;
        List<AnimatorListenerCompat> mListeners = new ArrayList();
        List<AnimatorUpdateListenerCompat> mUpdateListeners = new ArrayList();
        private long mDuration = 200;
        private float mFraction = 0.0f;
        private boolean mStarted = false;
        private boolean mEnded = false;
        private Runnable mLoopRunnable = new Runnable() { // from class: android.support.v4.animation.DonutAnimatorCompatProvider.DonutFloatValueAnimator.1
            @Override // java.lang.Runnable
            public void run() {
                long dt = DonutFloatValueAnimator.this.getTime() - DonutFloatValueAnimator.this.mStartTime;
                float fraction = (((float) dt) * 1.0f) / ((float) DonutFloatValueAnimator.this.mDuration);
                fraction = (fraction > 1.0f || DonutFloatValueAnimator.this.mTarget.getParent() == null) ? 1.0f : 1.0f;
                DonutFloatValueAnimator.this.mFraction = fraction;
                DonutFloatValueAnimator.this.notifyUpdateListeners();
                if (DonutFloatValueAnimator.this.mFraction >= 1.0f) {
                    DonutFloatValueAnimator.this.dispatchEnd();
                } else {
                    DonutFloatValueAnimator.this.mTarget.postDelayed(DonutFloatValueAnimator.this.mLoopRunnable, 16L);
                }
            }
        };

        /* JADX INFO: Access modifiers changed from: private */
        public void notifyUpdateListeners() {
            for (int i = this.mUpdateListeners.size() - 1; i >= 0; i--) {
                this.mUpdateListeners.get(i).onAnimationUpdate(this);
            }
        }

        @Override // android.support.v4.animation.ValueAnimatorCompat
        public void setTarget(View view) {
            this.mTarget = view;
        }

        @Override // android.support.v4.animation.ValueAnimatorCompat
        public void addListener(AnimatorListenerCompat listener) {
            this.mListeners.add(listener);
        }

        @Override // android.support.v4.animation.ValueAnimatorCompat
        public void setDuration(long duration) {
            if (!this.mStarted) {
                this.mDuration = duration;
            }
        }

        @Override // android.support.v4.animation.ValueAnimatorCompat
        public void start() {
            if (!this.mStarted) {
                this.mStarted = true;
                dispatchStart();
                this.mFraction = 0.0f;
                this.mStartTime = getTime();
                this.mTarget.postDelayed(this.mLoopRunnable, 16L);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public long getTime() {
            return this.mTarget.getDrawingTime();
        }

        private void dispatchStart() {
            for (int i = this.mListeners.size() - 1; i >= 0; i--) {
                this.mListeners.get(i).onAnimationStart(this);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void dispatchEnd() {
            for (int i = this.mListeners.size() - 1; i >= 0; i--) {
                this.mListeners.get(i).onAnimationEnd(this);
            }
        }

        private void dispatchCancel() {
            for (int i = this.mListeners.size() - 1; i >= 0; i--) {
                this.mListeners.get(i).onAnimationCancel(this);
            }
        }

        @Override // android.support.v4.animation.ValueAnimatorCompat
        public void cancel() {
            if (!this.mEnded) {
                this.mEnded = true;
                if (this.mStarted) {
                    dispatchCancel();
                }
                dispatchEnd();
            }
        }

        @Override // android.support.v4.animation.ValueAnimatorCompat
        public void addUpdateListener(AnimatorUpdateListenerCompat animatorUpdateListener) {
            this.mUpdateListeners.add(animatorUpdateListener);
        }

        @Override // android.support.v4.animation.ValueAnimatorCompat
        public float getAnimatedFraction() {
            return this.mFraction;
        }
    }

    @Override // android.support.v4.animation.AnimatorProvider
    public void clearInterpolator(View view) {
    }
}
