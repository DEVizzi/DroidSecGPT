package android.support.design.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.StyleRes;
import android.support.design.R;
import android.support.design.widget.ValueAnimatorCompat;
import android.support.v4.view.AccessibilityDelegateCompat;
import android.support.v4.view.GravityCompat;
import android.support.v4.view.ViewCompat;
import android.support.v4.view.ViewPropertyAnimatorListenerAdapter;
import android.support.v4.view.accessibility.AccessibilityNodeInfoCompat;
import android.support.v7.internal.widget.TintManager;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;
import android.view.animation.AccelerateInterpolator;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
/* loaded from: classes.dex */
public class TextInputLayout extends LinearLayout {
    private static final int ANIMATION_DURATION = 200;
    private static final int INVALID_MAX_LENGTH = -1;
    private ValueAnimatorCompat mAnimator;
    private final CollapsingTextHelper mCollapsingTextHelper;
    private boolean mCounterEnabled;
    private int mCounterMaxLength;
    private int mCounterOverflowTextAppearance;
    private boolean mCounterOverflowed;
    private int mCounterTextAppearance;
    private TextView mCounterView;
    private ColorStateList mDefaultTextColor;
    private EditText mEditText;
    private boolean mErrorEnabled;
    private boolean mErrorShown;
    private int mErrorTextAppearance;
    private TextView mErrorView;
    private ColorStateList mFocusedTextColor;
    private CharSequence mHint;
    private boolean mHintAnimationEnabled;
    private LinearLayout mIndicatorArea;
    private Paint mTmpPaint;

    public TextInputLayout(Context context) {
        this(context, null);
    }

    public TextInputLayout(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public TextInputLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs);
        this.mCollapsingTextHelper = new CollapsingTextHelper(this);
        ThemeUtils.checkAppCompatTheme(context);
        setOrientation(1);
        setWillNotDraw(false);
        setAddStatesFromChildren(true);
        this.mCollapsingTextHelper.setTextSizeInterpolator(AnimationUtils.FAST_OUT_SLOW_IN_INTERPOLATOR);
        this.mCollapsingTextHelper.setPositionInterpolator(new AccelerateInterpolator());
        this.mCollapsingTextHelper.setCollapsedTextGravity(8388659);
        TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.TextInputLayout, defStyleAttr, R.style.Widget_Design_TextInputLayout);
        setHint(a.getText(R.styleable.TextInputLayout_android_hint));
        this.mHintAnimationEnabled = a.getBoolean(R.styleable.TextInputLayout_hintAnimationEnabled, true);
        if (a.hasValue(R.styleable.TextInputLayout_android_textColorHint)) {
            ColorStateList colorStateList = a.getColorStateList(R.styleable.TextInputLayout_android_textColorHint);
            this.mFocusedTextColor = colorStateList;
            this.mDefaultTextColor = colorStateList;
        }
        int hintAppearance = a.getResourceId(R.styleable.TextInputLayout_hintTextAppearance, -1);
        if (hintAppearance != -1) {
            setHintTextAppearance(a.getResourceId(R.styleable.TextInputLayout_hintTextAppearance, 0));
        }
        this.mErrorTextAppearance = a.getResourceId(R.styleable.TextInputLayout_errorTextAppearance, 0);
        boolean errorEnabled = a.getBoolean(R.styleable.TextInputLayout_errorEnabled, false);
        boolean counterEnabled = a.getBoolean(R.styleable.TextInputLayout_counterEnabled, false);
        setCounterMaxLength(a.getInt(R.styleable.TextInputLayout_counterMaxLength, -1));
        this.mCounterTextAppearance = a.getResourceId(R.styleable.TextInputLayout_counterTextAppearance, 0);
        this.mCounterOverflowTextAppearance = a.getResourceId(R.styleable.TextInputLayout_counterOverflowTextAppearance, 0);
        a.recycle();
        setErrorEnabled(errorEnabled);
        setCounterEnabled(counterEnabled);
        if (ViewCompat.getImportantForAccessibility(this) == 0) {
            ViewCompat.setImportantForAccessibility(this, 1);
        }
        ViewCompat.setAccessibilityDelegate(this, new TextInputAccessibilityDelegate());
    }

    @Override // android.view.ViewGroup
    public void addView(View child, int index, ViewGroup.LayoutParams params) {
        if (child instanceof EditText) {
            setEditText((EditText) child);
            super.addView(child, 0, updateEditTextMargin(params));
            return;
        }
        super.addView(child, index, params);
    }

    public void setTypeface(@Nullable Typeface typeface) {
        this.mCollapsingTextHelper.setTypefaces(typeface);
    }

    @NonNull
    public Typeface getTypeface() {
        return this.mCollapsingTextHelper.getCollapsedTypeface();
    }

    private void setEditText(EditText editText) {
        if (this.mEditText != null) {
            throw new IllegalArgumentException("We already have an EditText, can only have one");
        }
        this.mEditText = editText;
        this.mCollapsingTextHelper.setTypefaces(this.mEditText.getTypeface());
        this.mCollapsingTextHelper.setExpandedTextSize(this.mEditText.getTextSize());
        this.mCollapsingTextHelper.setExpandedTextGravity(this.mEditText.getGravity());
        this.mEditText.addTextChangedListener(new TextWatcher() { // from class: android.support.design.widget.TextInputLayout.1
            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
                TextInputLayout.this.updateLabelVisibility(true);
                if (TextInputLayout.this.mCounterEnabled) {
                    TextInputLayout.this.updateCounter(s.length());
                }
            }

            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }
        });
        if (this.mDefaultTextColor == null) {
            this.mDefaultTextColor = this.mEditText.getHintTextColors();
        }
        if (TextUtils.isEmpty(this.mHint)) {
            setHint(this.mEditText.getHint());
            this.mEditText.setHint((CharSequence) null);
        }
        if (this.mCounterView != null) {
            updateCounter(this.mEditText.getText().length());
        }
        if (this.mIndicatorArea != null) {
            adjustIndicatorPadding();
        }
        updateLabelVisibility(false);
    }

    private LinearLayout.LayoutParams updateEditTextMargin(ViewGroup.LayoutParams lp) {
        LinearLayout.LayoutParams llp = lp instanceof LinearLayout.LayoutParams ? (LinearLayout.LayoutParams) lp : new LinearLayout.LayoutParams(lp);
        if (this.mTmpPaint == null) {
            this.mTmpPaint = new Paint();
        }
        this.mTmpPaint.setTypeface(this.mCollapsingTextHelper.getCollapsedTypeface());
        this.mTmpPaint.setTextSize(this.mCollapsingTextHelper.getCollapsedTextSize());
        llp.topMargin = (int) (-this.mTmpPaint.ascent());
        return llp;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateLabelVisibility(boolean animate) {
        boolean hasText = (this.mEditText == null || TextUtils.isEmpty(this.mEditText.getText())) ? false : true;
        boolean isFocused = arrayContains(getDrawableState(), 16842908);
        boolean isErrorShowing = !TextUtils.isEmpty(getError());
        if (this.mDefaultTextColor != null && this.mFocusedTextColor != null) {
            this.mCollapsingTextHelper.setExpandedTextColor(this.mDefaultTextColor.getDefaultColor());
            this.mCollapsingTextHelper.setCollapsedTextColor(isFocused ? this.mFocusedTextColor.getDefaultColor() : this.mDefaultTextColor.getDefaultColor());
        }
        if (hasText || isFocused || isErrorShowing) {
            collapseHint(animate);
        } else {
            expandHint(animate);
        }
    }

    @Nullable
    public EditText getEditText() {
        return this.mEditText;
    }

    public void setHint(@Nullable CharSequence hint) {
        this.mHint = hint;
        this.mCollapsingTextHelper.setText(hint);
        sendAccessibilityEvent(2048);
    }

    @Nullable
    public CharSequence getHint() {
        return this.mHint;
    }

    public void setHintTextAppearance(@StyleRes int resId) {
        this.mCollapsingTextHelper.setCollapsedTextAppearance(resId);
        this.mFocusedTextColor = ColorStateList.valueOf(this.mCollapsingTextHelper.getCollapsedTextColor());
        if (this.mEditText != null) {
            updateLabelVisibility(false);
            LinearLayout.LayoutParams lp = updateEditTextMargin(this.mEditText.getLayoutParams());
            this.mEditText.setLayoutParams(lp);
            this.mEditText.requestLayout();
        }
    }

    private void addIndicator(TextView indicator, int index, LinearLayout.LayoutParams params) {
        if (this.mIndicatorArea == null) {
            this.mIndicatorArea = new LinearLayout(getContext());
            this.mIndicatorArea.setOrientation(0);
            addView(this.mIndicatorArea);
            if (this.mEditText != null) {
                adjustIndicatorPadding();
            }
        }
        this.mIndicatorArea.addView(indicator, index, params);
    }

    private void adjustIndicatorPadding() {
        ViewCompat.setPaddingRelative(this.mIndicatorArea, ViewCompat.getPaddingStart(this.mEditText), 0, ViewCompat.getPaddingEnd(this.mEditText), this.mEditText.getPaddingBottom());
    }

    private void removeIndicator(TextView indicator) {
        this.mIndicatorArea.removeView(indicator);
        if (this.mIndicatorArea.getChildCount() == 0) {
            removeView(this.mIndicatorArea);
        }
    }

    public void setErrorEnabled(boolean enabled) {
        if (this.mErrorEnabled != enabled) {
            if (this.mErrorView != null) {
                ViewCompat.animate(this.mErrorView).cancel();
            }
            if (enabled) {
                this.mErrorView = new TextView(getContext());
                this.mErrorView.setTextAppearance(getContext(), this.mErrorTextAppearance);
                this.mErrorView.setVisibility(4);
                ViewCompat.setAccessibilityLiveRegion(this.mErrorView, 1);
                LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, -2);
                params.weight = 1.0f;
                addIndicator(this.mErrorView, 0, params);
            } else {
                this.mErrorShown = false;
                updateEditTextBackground();
                removeIndicator(this.mErrorView);
                this.mErrorView = null;
            }
            this.mErrorEnabled = enabled;
        }
    }

    public boolean isErrorEnabled() {
        return this.mErrorEnabled;
    }

    public void setError(@Nullable CharSequence error) {
        if (!this.mErrorEnabled) {
            if (!TextUtils.isEmpty(error)) {
                setErrorEnabled(true);
            } else {
                return;
            }
        }
        if (!TextUtils.isEmpty(error)) {
            ViewCompat.setAlpha(this.mErrorView, 0.0f);
            this.mErrorView.setText(error);
            ViewCompat.animate(this.mErrorView).alpha(1.0f).setDuration(200L).setInterpolator(AnimationUtils.FAST_OUT_SLOW_IN_INTERPOLATOR).setListener(new ViewPropertyAnimatorListenerAdapter() { // from class: android.support.design.widget.TextInputLayout.2
                @Override // android.support.v4.view.ViewPropertyAnimatorListenerAdapter, android.support.v4.view.ViewPropertyAnimatorListener
                public void onAnimationStart(View view) {
                    view.setVisibility(0);
                }
            }).start();
            this.mErrorShown = true;
            updateEditTextBackground();
            updateLabelVisibility(true);
        } else if (this.mErrorView.getVisibility() == 0) {
            ViewCompat.animate(this.mErrorView).alpha(0.0f).setDuration(200L).setInterpolator(AnimationUtils.FAST_OUT_SLOW_IN_INTERPOLATOR).setListener(new ViewPropertyAnimatorListenerAdapter() { // from class: android.support.design.widget.TextInputLayout.3
                @Override // android.support.v4.view.ViewPropertyAnimatorListenerAdapter, android.support.v4.view.ViewPropertyAnimatorListener
                public void onAnimationEnd(View view) {
                    view.setVisibility(4);
                    TextInputLayout.this.updateLabelVisibility(true);
                }
            }).start();
            this.mErrorShown = false;
            updateEditTextBackground();
        }
    }

    public void setCounterEnabled(boolean enabled) {
        if (this.mCounterEnabled != enabled) {
            if (enabled) {
                this.mCounterView = new TextView(getContext());
                this.mCounterView.setMaxLines(1);
                this.mCounterView.setTextAppearance(getContext(), this.mCounterTextAppearance);
                LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-2, -2);
                params.gravity = (params.gravity & 112) | GravityCompat.END;
                ViewCompat.setAccessibilityLiveRegion(this.mCounterView, 1);
                addIndicator(this.mCounterView, -1, params);
                if (this.mEditText == null) {
                    updateCounter(0);
                } else {
                    updateCounter(this.mEditText.getText().length());
                }
            } else {
                removeIndicator(this.mCounterView);
                this.mCounterView = null;
            }
            this.mCounterEnabled = enabled;
        }
    }

    public void setCounterMaxLength(int maxLength) {
        if (this.mCounterMaxLength != maxLength) {
            if (maxLength > 0) {
                this.mCounterMaxLength = maxLength;
            } else {
                this.mCounterMaxLength = -1;
            }
            if (this.mCounterEnabled) {
                updateCounter(this.mEditText == null ? 0 : this.mEditText.getText().length());
            }
        }
    }

    public int getCounterMaxLength() {
        return this.mCounterMaxLength;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateCounter(int length) {
        boolean wasCounterOverflowed = this.mCounterOverflowed;
        if (this.mCounterMaxLength == -1) {
            this.mCounterView.setText(String.valueOf(length));
            this.mCounterOverflowed = false;
        } else {
            this.mCounterOverflowed = length > this.mCounterMaxLength;
            if (wasCounterOverflowed != this.mCounterOverflowed) {
                this.mCounterView.setTextAppearance(getContext(), this.mCounterOverflowed ? this.mCounterOverflowTextAppearance : this.mCounterTextAppearance);
            }
            this.mCounterView.setText(getContext().getString(R.string.character_counter_pattern, Integer.valueOf(length), Integer.valueOf(this.mCounterMaxLength)));
        }
        if (this.mEditText != null && wasCounterOverflowed != this.mCounterOverflowed) {
            updateEditTextBackground();
        }
    }

    private void updateEditTextBackground() {
        if (this.mErrorShown && this.mErrorView != null) {
            ViewCompat.setBackgroundTintList(this.mEditText, ColorStateList.valueOf(this.mErrorView.getCurrentTextColor()));
        } else if (this.mCounterOverflowed && this.mCounterView != null) {
            ViewCompat.setBackgroundTintList(this.mEditText, ColorStateList.valueOf(this.mCounterView.getCurrentTextColor()));
        } else {
            TintManager tintManager = TintManager.get(getContext());
            ViewCompat.setBackgroundTintList(this.mEditText, tintManager.getTintList(R.drawable.abc_edit_text_material));
        }
    }

    @Nullable
    public CharSequence getError() {
        if (this.mErrorEnabled && this.mErrorView != null && this.mErrorView.getVisibility() == 0) {
            return this.mErrorView.getText();
        }
        return null;
    }

    public boolean isHintAnimationEnabled() {
        return this.mHintAnimationEnabled;
    }

    public void setHintAnimationEnabled(boolean enabled) {
        this.mHintAnimationEnabled = enabled;
    }

    @Override // android.view.View
    public void draw(Canvas canvas) {
        super.draw(canvas);
        this.mCollapsingTextHelper.draw(canvas);
    }

    @Override // android.widget.LinearLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        if (this.mEditText != null) {
            int l = this.mEditText.getLeft() + this.mEditText.getCompoundPaddingLeft();
            int r = this.mEditText.getRight() - this.mEditText.getCompoundPaddingRight();
            this.mCollapsingTextHelper.setExpandedBounds(l, this.mEditText.getTop() + this.mEditText.getCompoundPaddingTop(), r, this.mEditText.getBottom() - this.mEditText.getCompoundPaddingBottom());
            this.mCollapsingTextHelper.setCollapsedBounds(l, getPaddingTop(), r, (bottom - top) - getPaddingBottom());
            this.mCollapsingTextHelper.recalculate();
        }
    }

    @Override // android.view.View
    public void refreshDrawableState() {
        super.refreshDrawableState();
        updateLabelVisibility(ViewCompat.isLaidOut(this));
    }

    private void collapseHint(boolean animate) {
        if (this.mAnimator != null && this.mAnimator.isRunning()) {
            this.mAnimator.cancel();
        }
        if (animate && this.mHintAnimationEnabled) {
            animateToExpansionFraction(1.0f);
        } else {
            this.mCollapsingTextHelper.setExpansionFraction(1.0f);
        }
    }

    private void expandHint(boolean animate) {
        if (this.mAnimator != null && this.mAnimator.isRunning()) {
            this.mAnimator.cancel();
        }
        if (animate && this.mHintAnimationEnabled) {
            animateToExpansionFraction(0.0f);
        } else {
            this.mCollapsingTextHelper.setExpansionFraction(0.0f);
        }
    }

    private void animateToExpansionFraction(float target) {
        if (this.mCollapsingTextHelper.getExpansionFraction() != target) {
            if (this.mAnimator == null) {
                this.mAnimator = ViewUtils.createAnimator();
                this.mAnimator.setInterpolator(AnimationUtils.LINEAR_INTERPOLATOR);
                this.mAnimator.setDuration(200);
                this.mAnimator.setUpdateListener(new ValueAnimatorCompat.AnimatorUpdateListener() { // from class: android.support.design.widget.TextInputLayout.4
                    @Override // android.support.design.widget.ValueAnimatorCompat.AnimatorUpdateListener
                    public void onAnimationUpdate(ValueAnimatorCompat animator) {
                        TextInputLayout.this.mCollapsingTextHelper.setExpansionFraction(animator.getAnimatedFloatValue());
                    }
                });
            }
            this.mAnimator.setFloatValues(this.mCollapsingTextHelper.getExpansionFraction(), target);
            this.mAnimator.start();
        }
    }

    private int getThemeAttrColor(int attr) {
        TypedValue tv = new TypedValue();
        if (getContext().getTheme().resolveAttribute(attr, tv, true)) {
            return tv.data;
        }
        return -65281;
    }

    /* loaded from: classes.dex */
    private class TextInputAccessibilityDelegate extends AccessibilityDelegateCompat {
        private TextInputAccessibilityDelegate() {
        }

        @Override // android.support.v4.view.AccessibilityDelegateCompat
        public void onInitializeAccessibilityEvent(View host, AccessibilityEvent event) {
            super.onInitializeAccessibilityEvent(host, event);
            event.setClassName(TextInputLayout.class.getSimpleName());
        }

        @Override // android.support.v4.view.AccessibilityDelegateCompat
        public void onPopulateAccessibilityEvent(View host, AccessibilityEvent event) {
            super.onPopulateAccessibilityEvent(host, event);
            CharSequence text = TextInputLayout.this.mCollapsingTextHelper.getText();
            if (!TextUtils.isEmpty(text)) {
                event.getText().add(text);
            }
        }

        @Override // android.support.v4.view.AccessibilityDelegateCompat
        public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
            CharSequence error;
            super.onInitializeAccessibilityNodeInfo(host, info);
            info.setClassName(TextInputLayout.class.getSimpleName());
            CharSequence text = TextInputLayout.this.mCollapsingTextHelper.getText();
            if (!TextUtils.isEmpty(text)) {
                info.setText(text);
            }
            if (TextInputLayout.this.mEditText != null) {
                info.setLabelFor(TextInputLayout.this.mEditText);
            }
            if (TextInputLayout.this.mErrorView != null) {
                error = TextInputLayout.this.mErrorView.getText();
            } else {
                error = null;
            }
            if (!TextUtils.isEmpty(error)) {
                info.setContentInvalid(true);
                info.setError(error);
            }
        }
    }

    private static boolean arrayContains(int[] array, int value) {
        for (int v : array) {
            if (v == value) {
                return true;
            }
        }
        return false;
    }
}
