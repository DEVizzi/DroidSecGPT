package android.support.design.widget;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.support.design.widget.ValueAnimatorCompat;
import android.view.animation.Interpolator;
/* loaded from: classes.dex */
class ValueAnimatorCompatImplHoneycombMr1 extends ValueAnimatorCompat.Impl {
    final ValueAnimator mValueAnimator = new ValueAnimator();

    @Override // android.support.design.widget.ValueAnimatorCompat.Impl
    public void start() {
        this.mValueAnimator.start();
    }

    @Override // android.support.design.widget.ValueAnimatorCompat.Impl
    public boolean isRunning() {
        return this.mValueAnimator.isRunning();
    }

    @Override // android.support.design.widget.ValueAnimatorCompat.Impl
    public void setInterpolator(Interpolator interpolator) {
        this.mValueAnimator.setInterpolator(interpolator);
    }

    @Override // android.support.design.widget.ValueAnimatorCompat.Impl
    public void setUpdateListener(final ValueAnimatorCompat.Impl.AnimatorUpdateListenerProxy updateListener) {
        this.mValueAnimator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: android.support.design.widget.ValueAnimatorCompatImplHoneycombMr1.1
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public void onAnimationUpdate(ValueAnimator valueAnimator) {
                updateListener.onAnimationUpdate();
            }
        });
    }

    @Override // android.support.design.widget.ValueAnimatorCompat.Impl
    public void setListener(final ValueAnimatorCompat.Impl.AnimatorListenerProxy listener) {
        this.mValueAnimator.addListener(new AnimatorListenerAdapter() { // from class: android.support.design.widget.ValueAnimatorCompatImplHoneycombMr1.2
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationStart(Animator animator) {
                listener.onAnimationStart();
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animator) {
                listener.onAnimationEnd();
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animator) {
                listener.onAnimationCancel();
            }
        });
    }

    @Override // android.support.design.widget.ValueAnimatorCompat.Impl
    public void setIntValues(int from, int to) {
        this.mValueAnimator.setIntValues(from, to);
    }

    @Override // android.support.design.widget.ValueAnimatorCompat.Impl
    public int getAnimatedIntValue() {
        return ((Integer) this.mValueAnimator.getAnimatedValue()).intValue();
    }

    @Override // android.support.design.widget.ValueAnimatorCompat.Impl
    public void setFloatValues(float from, float to) {
        this.mValueAnimator.setFloatValues(from, to);
    }

    @Override // android.support.design.widget.ValueAnimatorCompat.Impl
    public float getAnimatedFloatValue() {
        return ((Float) this.mValueAnimator.getAnimatedValue()).floatValue();
    }

    @Override // android.support.design.widget.ValueAnimatorCompat.Impl
    public void setDuration(int duration) {
        this.mValueAnimator.setDuration(duration);
    }

    @Override // android.support.design.widget.ValueAnimatorCompat.Impl
    public void cancel() {
        this.mValueAnimator.cancel();
    }

    @Override // android.support.design.widget.ValueAnimatorCompat.Impl
    public float getAnimatedFraction() {
        return this.mValueAnimator.getAnimatedFraction();
    }

    @Override // android.support.design.widget.ValueAnimatorCompat.Impl
    public void end() {
        this.mValueAnimator.end();
    }

    @Override // android.support.design.widget.ValueAnimatorCompat.Impl
    public long getDuration() {
        return this.mValueAnimator.getDuration();
    }
}
