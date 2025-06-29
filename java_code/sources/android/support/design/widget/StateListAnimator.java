package android.support.design.widget;

import android.util.StateSet;
import android.view.View;
import android.view.animation.Animation;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
/* loaded from: classes.dex */
final class StateListAnimator {
    private WeakReference<View> mViewRef;
    private final ArrayList<Tuple> mTuples = new ArrayList<>();
    private Tuple mLastMatch = null;
    private Animation mRunningAnimation = null;
    private Animation.AnimationListener mAnimationListener = new Animation.AnimationListener() { // from class: android.support.design.widget.StateListAnimator.1
        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationEnd(Animation animation) {
            if (StateListAnimator.this.mRunningAnimation == animation) {
                StateListAnimator.this.mRunningAnimation = null;
            }
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationStart(Animation animation) {
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationRepeat(Animation animation) {
        }
    };

    public void addState(int[] specs, Animation animation) {
        Tuple tuple = new Tuple(specs, animation);
        animation.setAnimationListener(this.mAnimationListener);
        this.mTuples.add(tuple);
    }

    Animation getRunningAnimation() {
        return this.mRunningAnimation;
    }

    View getTarget() {
        if (this.mViewRef == null) {
            return null;
        }
        return this.mViewRef.get();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setTarget(View view) {
        View current = getTarget();
        if (current != view) {
            if (current != null) {
                clearTarget();
            }
            if (view != null) {
                this.mViewRef = new WeakReference<>(view);
            }
        }
    }

    private void clearTarget() {
        View view = getTarget();
        int size = this.mTuples.size();
        for (int i = 0; i < size; i++) {
            Animation anim = this.mTuples.get(i).mAnimation;
            if (view.getAnimation() == anim) {
                view.clearAnimation();
            }
        }
        this.mViewRef = null;
        this.mLastMatch = null;
        this.mRunningAnimation = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setState(int[] state) {
        Tuple match = null;
        int count = this.mTuples.size();
        int i = 0;
        while (true) {
            if (i >= count) {
                break;
            }
            Tuple tuple = this.mTuples.get(i);
            if (!StateSet.stateSetMatches(tuple.mSpecs, state)) {
                i++;
            } else {
                match = tuple;
                break;
            }
        }
        if (match != this.mLastMatch) {
            if (this.mLastMatch != null) {
                cancel();
            }
            this.mLastMatch = match;
            View view = this.mViewRef.get();
            if (match != null && view != null && view.getVisibility() == 0) {
                start(match);
            }
        }
    }

    private void start(Tuple match) {
        this.mRunningAnimation = match.mAnimation;
        View view = getTarget();
        if (view != null) {
            view.startAnimation(this.mRunningAnimation);
        }
    }

    private void cancel() {
        if (this.mRunningAnimation != null) {
            View view = getTarget();
            if (view != null && view.getAnimation() == this.mRunningAnimation) {
                view.clearAnimation();
            }
            this.mRunningAnimation = null;
        }
    }

    ArrayList<Tuple> getTuples() {
        return this.mTuples;
    }

    public void jumpToCurrentState() {
        View view;
        if (this.mRunningAnimation != null && (view = getTarget()) != null && view.getAnimation() == this.mRunningAnimation) {
            view.clearAnimation();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class Tuple {
        final Animation mAnimation;
        final int[] mSpecs;

        private Tuple(int[] specs, Animation Animation) {
            this.mSpecs = specs;
            this.mAnimation = Animation;
        }

        int[] getSpecs() {
            return this.mSpecs;
        }

        Animation getAnimation() {
            return this.mAnimation;
        }
    }
}
