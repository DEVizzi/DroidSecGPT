package android.support.design.widget;

import android.support.v4.view.animation.FastOutSlowInInterpolator;
import android.view.animation.Animation;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.Interpolator;
import android.view.animation.LinearInterpolator;
/* loaded from: classes.dex */
class AnimationUtils {
    static final Interpolator LINEAR_INTERPOLATOR = new LinearInterpolator();
    static final Interpolator FAST_OUT_SLOW_IN_INTERPOLATOR = new FastOutSlowInInterpolator();
    static final Interpolator DECELERATE_INTERPOLATOR = new DecelerateInterpolator();

    AnimationUtils() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static float lerp(float startValue, float endValue, float fraction) {
        return ((endValue - startValue) * fraction) + startValue;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int lerp(int startValue, int endValue, float fraction) {
        return Math.round((endValue - startValue) * fraction) + startValue;
    }

    /* loaded from: classes.dex */
    static class AnimationListenerAdapter implements Animation.AnimationListener {
        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationStart(Animation animation) {
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationEnd(Animation animation) {
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationRepeat(Animation animation) {
        }
    }
}
