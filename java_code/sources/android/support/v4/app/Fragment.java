package android.support.v4.app;

import android.app.Activity;
import android.content.ComponentCallbacks;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.StringRes;
import android.support.v4.util.DebugUtils;
import android.support.v4.util.SimpleArrayMap;
import android.support.v4.view.LayoutInflaterCompat;
import android.util.AttributeSet;
import android.util.SparseArray;
import android.view.ContextMenu;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Animation;
import java.io.FileDescriptor;
import java.io.PrintWriter;
/* loaded from: classes.dex */
public class Fragment implements ComponentCallbacks, View.OnCreateContextMenuListener {
    static final int ACTIVITY_CREATED = 2;
    static final int CREATED = 1;
    static final int INITIALIZING = 0;
    static final int RESUMED = 5;
    static final int STARTED = 4;
    static final int STOPPED = 3;
    boolean mAdded;
    Boolean mAllowEnterTransitionOverlap;
    Boolean mAllowReturnTransitionOverlap;
    View mAnimatingAway;
    Bundle mArguments;
    int mBackStackNesting;
    boolean mCalled;
    boolean mCheckedForLoaderManager;
    FragmentManagerImpl mChildFragmentManager;
    ViewGroup mContainer;
    int mContainerId;
    boolean mDeferStart;
    boolean mDetached;
    int mFragmentId;
    FragmentManagerImpl mFragmentManager;
    boolean mFromLayout;
    boolean mHasMenu;
    boolean mHidden;
    FragmentHostCallback mHost;
    boolean mInLayout;
    View mInnerView;
    LoaderManagerImpl mLoaderManager;
    boolean mLoadersStarted;
    int mNextAnim;
    Fragment mParentFragment;
    boolean mRemoving;
    boolean mRestored;
    boolean mResumed;
    boolean mRetainInstance;
    boolean mRetainLoader;
    boolean mRetaining;
    Bundle mSavedFragmentState;
    SparseArray<Parcelable> mSavedViewState;
    int mStateAfterAnimating;
    String mTag;
    Fragment mTarget;
    int mTargetRequestCode;
    View mView;
    String mWho;
    private static final SimpleArrayMap<String, Class<?>> sClassMap = new SimpleArrayMap<>();
    static final Object USE_DEFAULT_TRANSITION = new Object();
    int mState = 0;
    int mIndex = -1;
    int mTargetIndex = -1;
    boolean mMenuVisible = true;
    boolean mUserVisibleHint = true;
    Object mEnterTransition = null;
    Object mReturnTransition = USE_DEFAULT_TRANSITION;
    Object mExitTransition = null;
    Object mReenterTransition = USE_DEFAULT_TRANSITION;
    Object mSharedElementEnterTransition = null;
    Object mSharedElementReturnTransition = USE_DEFAULT_TRANSITION;
    SharedElementCallback mEnterTransitionCallback = null;
    SharedElementCallback mExitTransitionCallback = null;

    /* loaded from: classes.dex */
    public static class SavedState implements Parcelable {
        public static final Parcelable.Creator<SavedState> CREATOR = new Parcelable.Creator<SavedState>() { // from class: android.support.v4.app.Fragment.SavedState.1
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.os.Parcelable.Creator
            public SavedState createFromParcel(Parcel in) {
                return new SavedState(in, null);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.os.Parcelable.Creator
            public SavedState[] newArray(int size) {
                return new SavedState[size];
            }
        };
        final Bundle mState;

        /* JADX INFO: Access modifiers changed from: package-private */
        public SavedState(Bundle state) {
            this.mState = state;
        }

        SavedState(Parcel in, ClassLoader loader) {
            this.mState = in.readBundle();
            if (loader != null && this.mState != null) {
                this.mState.setClassLoader(loader);
            }
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            return 0;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel dest, int flags) {
            dest.writeBundle(this.mState);
        }
    }

    /* loaded from: classes.dex */
    public static class InstantiationException extends RuntimeException {
        public InstantiationException(String msg, Exception cause) {
            super(msg, cause);
        }
    }

    public static Fragment instantiate(Context context, String fname) {
        return instantiate(context, fname, null);
    }

    public static Fragment instantiate(Context context, String fname, @Nullable Bundle args) {
        try {
            Class<?> clazz = sClassMap.get(fname);
            if (clazz == null) {
                clazz = context.getClassLoader().loadClass(fname);
                sClassMap.put(fname, clazz);
            }
            Fragment f = (Fragment) clazz.newInstance();
            if (args != null) {
                args.setClassLoader(f.getClass().getClassLoader());
                f.mArguments = args;
            }
            return f;
        } catch (ClassNotFoundException e) {
            throw new InstantiationException("Unable to instantiate fragment " + fname + ": make sure class name exists, is public, and has an empty constructor that is public", e);
        } catch (IllegalAccessException e2) {
            throw new InstantiationException("Unable to instantiate fragment " + fname + ": make sure class name exists, is public, and has an empty constructor that is public", e2);
        } catch (java.lang.InstantiationException e3) {
            throw new InstantiationException("Unable to instantiate fragment " + fname + ": make sure class name exists, is public, and has an empty constructor that is public", e3);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isSupportFragmentClass(Context context, String fname) {
        try {
            Class<?> clazz = sClassMap.get(fname);
            if (clazz == null) {
                clazz = context.getClassLoader().loadClass(fname);
                sClassMap.put(fname, clazz);
            }
            return Fragment.class.isAssignableFrom(clazz);
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final void restoreViewState(Bundle savedInstanceState) {
        if (this.mSavedViewState != null) {
            this.mInnerView.restoreHierarchyState(this.mSavedViewState);
            this.mSavedViewState = null;
        }
        this.mCalled = false;
        onViewStateRestored(savedInstanceState);
        if (!this.mCalled) {
            throw new SuperNotCalledException("Fragment " + this + " did not call through to super.onViewStateRestored()");
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final void setIndex(int index, Fragment parent) {
        this.mIndex = index;
        if (parent != null) {
            this.mWho = parent.mWho + ":" + this.mIndex;
        } else {
            this.mWho = "android:fragment:" + this.mIndex;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final boolean isInBackStack() {
        return this.mBackStackNesting > 0;
    }

    public final boolean equals(Object o) {
        return super.equals(o);
    }

    public final int hashCode() {
        return super.hashCode();
    }

    public String toString() {
        StringBuilder sb = new StringBuilder(128);
        DebugUtils.buildShortClassTag(this, sb);
        if (this.mIndex >= 0) {
            sb.append(" #");
            sb.append(this.mIndex);
        }
        if (this.mFragmentId != 0) {
            sb.append(" id=0x");
            sb.append(Integer.toHexString(this.mFragmentId));
        }
        if (this.mTag != null) {
            sb.append(" ");
            sb.append(this.mTag);
        }
        sb.append('}');
        return sb.toString();
    }

    public final int getId() {
        return this.mFragmentId;
    }

    public final String getTag() {
        return this.mTag;
    }

    public void setArguments(Bundle args) {
        if (this.mIndex >= 0) {
            throw new IllegalStateException("Fragment already active");
        }
        this.mArguments = args;
    }

    public final Bundle getArguments() {
        return this.mArguments;
    }

    public void setInitialSavedState(SavedState state) {
        if (this.mIndex >= 0) {
            throw new IllegalStateException("Fragment already active");
        }
        this.mSavedFragmentState = (state == null || state.mState == null) ? null : state.mState;
    }

    public void setTargetFragment(Fragment fragment, int requestCode) {
        this.mTarget = fragment;
        this.mTargetRequestCode = requestCode;
    }

    public final Fragment getTargetFragment() {
        return this.mTarget;
    }

    public final int getTargetRequestCode() {
        return this.mTargetRequestCode;
    }

    public Context getContext() {
        if (this.mHost == null) {
            return null;
        }
        return this.mHost.getContext();
    }

    public final FragmentActivity getActivity() {
        if (this.mHost == null) {
            return null;
        }
        return (FragmentActivity) this.mHost.getActivity();
    }

    public final Object getHost() {
        if (this.mHost == null) {
            return null;
        }
        return this.mHost.onGetHost();
    }

    public final Resources getResources() {
        if (this.mHost == null) {
            throw new IllegalStateException("Fragment " + this + " not attached to Activity");
        }
        return this.mHost.getContext().getResources();
    }

    public final CharSequence getText(@StringRes int resId) {
        return getResources().getText(resId);
    }

    public final String getString(@StringRes int resId) {
        return getResources().getString(resId);
    }

    public final String getString(@StringRes int resId, Object... formatArgs) {
        return getResources().getString(resId, formatArgs);
    }

    public final FragmentManager getFragmentManager() {
        return this.mFragmentManager;
    }

    public final FragmentManager getChildFragmentManager() {
        if (this.mChildFragmentManager == null) {
            instantiateChildFragmentManager();
            if (this.mState >= 5) {
                this.mChildFragmentManager.dispatchResume();
            } else if (this.mState >= 4) {
                this.mChildFragmentManager.dispatchStart();
            } else if (this.mState >= 2) {
                this.mChildFragmentManager.dispatchActivityCreated();
            } else if (this.mState >= 1) {
                this.mChildFragmentManager.dispatchCreate();
            }
        }
        return this.mChildFragmentManager;
    }

    public final Fragment getParentFragment() {
        return this.mParentFragment;
    }

    public final boolean isAdded() {
        return this.mHost != null && this.mAdded;
    }

    public final boolean isDetached() {
        return this.mDetached;
    }

    public final boolean isRemoving() {
        return this.mRemoving;
    }

    public final boolean isInLayout() {
        return this.mInLayout;
    }

    public final boolean isResumed() {
        return this.mResumed;
    }

    public final boolean isVisible() {
        return (!isAdded() || isHidden() || this.mView == null || this.mView.getWindowToken() == null || this.mView.getVisibility() != 0) ? false : true;
    }

    public final boolean isHidden() {
        return this.mHidden;
    }

    public final boolean hasOptionsMenu() {
        return this.mHasMenu;
    }

    public final boolean isMenuVisible() {
        return this.mMenuVisible;
    }

    public void onHiddenChanged(boolean hidden) {
    }

    public void setRetainInstance(boolean retain) {
        if (retain && this.mParentFragment != null) {
            throw new IllegalStateException("Can't retain fragements that are nested in other fragments");
        }
        this.mRetainInstance = retain;
    }

    public final boolean getRetainInstance() {
        return this.mRetainInstance;
    }

    public void setHasOptionsMenu(boolean hasMenu) {
        if (this.mHasMenu != hasMenu) {
            this.mHasMenu = hasMenu;
            if (isAdded() && !isHidden()) {
                this.mHost.onSupportInvalidateOptionsMenu();
            }
        }
    }

    public void setMenuVisibility(boolean menuVisible) {
        if (this.mMenuVisible != menuVisible) {
            this.mMenuVisible = menuVisible;
            if (this.mHasMenu && isAdded() && !isHidden()) {
                this.mHost.onSupportInvalidateOptionsMenu();
            }
        }
    }

    public void setUserVisibleHint(boolean isVisibleToUser) {
        if (!this.mUserVisibleHint && isVisibleToUser && this.mState < 4) {
            this.mFragmentManager.performPendingDeferredStart(this);
        }
        this.mUserVisibleHint = isVisibleToUser;
        this.mDeferStart = !isVisibleToUser;
    }

    public boolean getUserVisibleHint() {
        return this.mUserVisibleHint;
    }

    public LoaderManager getLoaderManager() {
        if (this.mLoaderManager != null) {
            return this.mLoaderManager;
        }
        if (this.mHost == null) {
            throw new IllegalStateException("Fragment " + this + " not attached to Activity");
        }
        this.mCheckedForLoaderManager = true;
        this.mLoaderManager = this.mHost.getLoaderManager(this.mWho, this.mLoadersStarted, true);
        return this.mLoaderManager;
    }

    public void startActivity(Intent intent) {
        if (this.mHost == null) {
            throw new IllegalStateException("Fragment " + this + " not attached to Activity");
        }
        this.mHost.onStartActivityFromFragment(this, intent, -1);
    }

    public void startActivityForResult(Intent intent, int requestCode) {
        if (this.mHost == null) {
            throw new IllegalStateException("Fragment " + this + " not attached to Activity");
        }
        this.mHost.onStartActivityFromFragment(this, intent, requestCode);
    }

    public void onActivityResult(int requestCode, int resultCode, Intent data) {
    }

    public final void requestPermissions(@NonNull String[] permissions, int requestCode) {
        if (this.mHost == null) {
            throw new IllegalStateException("Fragment " + this + " not attached to Activity");
        }
        this.mHost.onRequestPermissionsFromFragment(this, permissions, requestCode);
    }

    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
    }

    public boolean shouldShowRequestPermissionRationale(@NonNull String permission) {
        if (this.mHost != null) {
            return this.mHost.onShouldShowRequestPermissionRationale(permission);
        }
        return false;
    }

    public LayoutInflater getLayoutInflater(Bundle savedInstanceState) {
        LayoutInflater result = this.mHost.onGetLayoutInflater();
        getChildFragmentManager();
        LayoutInflaterCompat.setFactory(result, this.mChildFragmentManager.getLayoutInflaterFactory());
        return result;
    }

    public void onInflate(Context context, AttributeSet attrs, Bundle savedInstanceState) {
        this.mCalled = true;
        Activity hostActivity = this.mHost == null ? null : this.mHost.getActivity();
        if (hostActivity != null) {
            this.mCalled = false;
            onInflate(hostActivity, attrs, savedInstanceState);
        }
    }

    @Deprecated
    public void onInflate(Activity activity, AttributeSet attrs, Bundle savedInstanceState) {
        this.mCalled = true;
    }

    public void onAttach(Context context) {
        this.mCalled = true;
        Activity hostActivity = this.mHost == null ? null : this.mHost.getActivity();
        if (hostActivity != null) {
            this.mCalled = false;
            onAttach(hostActivity);
        }
    }

    @Deprecated
    public void onAttach(Activity activity) {
        this.mCalled = true;
    }

    public Animation onCreateAnimation(int transit, boolean enter, int nextAnim) {
        return null;
    }

    public void onCreate(@Nullable Bundle savedInstanceState) {
        this.mCalled = true;
    }

    @Nullable
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return null;
    }

    public void onViewCreated(View view, @Nullable Bundle savedInstanceState) {
    }

    @Nullable
    public View getView() {
        return this.mView;
    }

    public void onActivityCreated(@Nullable Bundle savedInstanceState) {
        this.mCalled = true;
    }

    public void onViewStateRestored(@Nullable Bundle savedInstanceState) {
        this.mCalled = true;
    }

    public void onStart() {
        this.mCalled = true;
        if (!this.mLoadersStarted) {
            this.mLoadersStarted = true;
            if (!this.mCheckedForLoaderManager) {
                this.mCheckedForLoaderManager = true;
                this.mLoaderManager = this.mHost.getLoaderManager(this.mWho, this.mLoadersStarted, false);
            }
            if (this.mLoaderManager != null) {
                this.mLoaderManager.doStart();
            }
        }
    }

    public void onResume() {
        this.mCalled = true;
    }

    public void onSaveInstanceState(Bundle outState) {
    }

    @Override // android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration newConfig) {
        this.mCalled = true;
    }

    public void onPause() {
        this.mCalled = true;
    }

    public void onStop() {
        this.mCalled = true;
    }

    @Override // android.content.ComponentCallbacks
    public void onLowMemory() {
        this.mCalled = true;
    }

    public void onDestroyView() {
        this.mCalled = true;
    }

    public void onDestroy() {
        this.mCalled = true;
        if (!this.mCheckedForLoaderManager) {
            this.mCheckedForLoaderManager = true;
            this.mLoaderManager = this.mHost.getLoaderManager(this.mWho, this.mLoadersStarted, false);
        }
        if (this.mLoaderManager != null) {
            this.mLoaderManager.doDestroy();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void initState() {
        this.mIndex = -1;
        this.mWho = null;
        this.mAdded = false;
        this.mRemoving = false;
        this.mResumed = false;
        this.mFromLayout = false;
        this.mInLayout = false;
        this.mRestored = false;
        this.mBackStackNesting = 0;
        this.mFragmentManager = null;
        this.mChildFragmentManager = null;
        this.mHost = null;
        this.mFragmentId = 0;
        this.mContainerId = 0;
        this.mTag = null;
        this.mHidden = false;
        this.mDetached = false;
        this.mRetaining = false;
        this.mLoaderManager = null;
        this.mLoadersStarted = false;
        this.mCheckedForLoaderManager = false;
    }

    public void onDetach() {
        this.mCalled = true;
    }

    public void onCreateOptionsMenu(Menu menu, MenuInflater inflater) {
    }

    public void onPrepareOptionsMenu(Menu menu) {
    }

    public void onDestroyOptionsMenu() {
    }

    public boolean onOptionsItemSelected(MenuItem item) {
        return false;
    }

    public void onOptionsMenuClosed(Menu menu) {
    }

    @Override // android.view.View.OnCreateContextMenuListener
    public void onCreateContextMenu(ContextMenu menu, View v, ContextMenu.ContextMenuInfo menuInfo) {
        getActivity().onCreateContextMenu(menu, v, menuInfo);
    }

    public void registerForContextMenu(View view) {
        view.setOnCreateContextMenuListener(this);
    }

    public void unregisterForContextMenu(View view) {
        view.setOnCreateContextMenuListener(null);
    }

    public boolean onContextItemSelected(MenuItem item) {
        return false;
    }

    public void setEnterSharedElementCallback(SharedElementCallback callback) {
        this.mEnterTransitionCallback = callback;
    }

    public void setExitSharedElementCallback(SharedElementCallback callback) {
        this.mExitTransitionCallback = callback;
    }

    public void setEnterTransition(Object transition) {
        this.mEnterTransition = transition;
    }

    public Object getEnterTransition() {
        return this.mEnterTransition;
    }

    public void setReturnTransition(Object transition) {
        this.mReturnTransition = transition;
    }

    public Object getReturnTransition() {
        return this.mReturnTransition == USE_DEFAULT_TRANSITION ? getEnterTransition() : this.mReturnTransition;
    }

    public void setExitTransition(Object transition) {
        this.mExitTransition = transition;
    }

    public Object getExitTransition() {
        return this.mExitTransition;
    }

    public void setReenterTransition(Object transition) {
        this.mReenterTransition = transition;
    }

    public Object getReenterTransition() {
        return this.mReenterTransition == USE_DEFAULT_TRANSITION ? getExitTransition() : this.mReenterTransition;
    }

    public void setSharedElementEnterTransition(Object transition) {
        this.mSharedElementEnterTransition = transition;
    }

    public Object getSharedElementEnterTransition() {
        return this.mSharedElementEnterTransition;
    }

    public void setSharedElementReturnTransition(Object transition) {
        this.mSharedElementReturnTransition = transition;
    }

    public Object getSharedElementReturnTransition() {
        return this.mSharedElementReturnTransition == USE_DEFAULT_TRANSITION ? getSharedElementEnterTransition() : this.mSharedElementReturnTransition;
    }

    public void setAllowEnterTransitionOverlap(boolean allow) {
        this.mAllowEnterTransitionOverlap = Boolean.valueOf(allow);
    }

    public boolean getAllowEnterTransitionOverlap() {
        if (this.mAllowEnterTransitionOverlap == null) {
            return true;
        }
        return this.mAllowEnterTransitionOverlap.booleanValue();
    }

    public void setAllowReturnTransitionOverlap(boolean allow) {
        this.mAllowReturnTransitionOverlap = Boolean.valueOf(allow);
    }

    public boolean getAllowReturnTransitionOverlap() {
        if (this.mAllowReturnTransitionOverlap == null) {
            return true;
        }
        return this.mAllowReturnTransitionOverlap.booleanValue();
    }

    public void dump(String prefix, FileDescriptor fd, PrintWriter writer, String[] args) {
        writer.print(prefix);
        writer.print("mFragmentId=#");
        writer.print(Integer.toHexString(this.mFragmentId));
        writer.print(" mContainerId=#");
        writer.print(Integer.toHexString(this.mContainerId));
        writer.print(" mTag=");
        writer.println(this.mTag);
        writer.print(prefix);
        writer.print("mState=");
        writer.print(this.mState);
        writer.print(" mIndex=");
        writer.print(this.mIndex);
        writer.print(" mWho=");
        writer.print(this.mWho);
        writer.print(" mBackStackNesting=");
        writer.println(this.mBackStackNesting);
        writer.print(prefix);
        writer.print("mAdded=");
        writer.print(this.mAdded);
        writer.print(" mRemoving=");
        writer.print(this.mRemoving);
        writer.print(" mResumed=");
        writer.print(this.mResumed);
        writer.print(" mFromLayout=");
        writer.print(this.mFromLayout);
        writer.print(" mInLayout=");
        writer.println(this.mInLayout);
        writer.print(prefix);
        writer.print("mHidden=");
        writer.print(this.mHidden);
        writer.print(" mDetached=");
        writer.print(this.mDetached);
        writer.print(" mMenuVisible=");
        writer.print(this.mMenuVisible);
        writer.print(" mHasMenu=");
        writer.println(this.mHasMenu);
        writer.print(prefix);
        writer.print("mRetainInstance=");
        writer.print(this.mRetainInstance);
        writer.print(" mRetaining=");
        writer.print(this.mRetaining);
        writer.print(" mUserVisibleHint=");
        writer.println(this.mUserVisibleHint);
        if (this.mFragmentManager != null) {
            writer.print(prefix);
            writer.print("mFragmentManager=");
            writer.println(this.mFragmentManager);
        }
        if (this.mHost != null) {
            writer.print(prefix);
            writer.print("mHost=");
            writer.println(this.mHost);
        }
        if (this.mParentFragment != null) {
            writer.print(prefix);
            writer.print("mParentFragment=");
            writer.println(this.mParentFragment);
        }
        if (this.mArguments != null) {
            writer.print(prefix);
            writer.print("mArguments=");
            writer.println(this.mArguments);
        }
        if (this.mSavedFragmentState != null) {
            writer.print(prefix);
            writer.print("mSavedFragmentState=");
            writer.println(this.mSavedFragmentState);
        }
        if (this.mSavedViewState != null) {
            writer.print(prefix);
            writer.print("mSavedViewState=");
            writer.println(this.mSavedViewState);
        }
        if (this.mTarget != null) {
            writer.print(prefix);
            writer.print("mTarget=");
            writer.print(this.mTarget);
            writer.print(" mTargetRequestCode=");
            writer.println(this.mTargetRequestCode);
        }
        if (this.mNextAnim != 0) {
            writer.print(prefix);
            writer.print("mNextAnim=");
            writer.println(this.mNextAnim);
        }
        if (this.mContainer != null) {
            writer.print(prefix);
            writer.print("mContainer=");
            writer.println(this.mContainer);
        }
        if (this.mView != null) {
            writer.print(prefix);
            writer.print("mView=");
            writer.println(this.mView);
        }
        if (this.mInnerView != null) {
            writer.print(prefix);
            writer.print("mInnerView=");
            writer.println(this.mView);
        }
        if (this.mAnimatingAway != null) {
            writer.print(prefix);
            writer.print("mAnimatingAway=");
            writer.println(this.mAnimatingAway);
            writer.print(prefix);
            writer.print("mStateAfterAnimating=");
            writer.println(this.mStateAfterAnimating);
        }
        if (this.mLoaderManager != null) {
            writer.print(prefix);
            writer.println("Loader Manager:");
            this.mLoaderManager.dump(prefix + "  ", fd, writer, args);
        }
        if (this.mChildFragmentManager != null) {
            writer.print(prefix);
            writer.println("Child " + this.mChildFragmentManager + ":");
            this.mChildFragmentManager.dump(prefix + "  ", fd, writer, args);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Fragment findFragmentByWho(String who) {
        if (!who.equals(this.mWho)) {
            if (this.mChildFragmentManager != null) {
                return this.mChildFragmentManager.findFragmentByWho(who);
            }
            return null;
        }
        return this;
    }

    void instantiateChildFragmentManager() {
        this.mChildFragmentManager = new FragmentManagerImpl();
        this.mChildFragmentManager.attachController(this.mHost, new FragmentContainer() { // from class: android.support.v4.app.Fragment.1
            @Override // android.support.v4.app.FragmentContainer
            @Nullable
            public View onFindViewById(int id) {
                if (Fragment.this.mView == null) {
                    throw new IllegalStateException("Fragment does not have a view");
                }
                return Fragment.this.mView.findViewById(id);
            }

            @Override // android.support.v4.app.FragmentContainer
            public boolean onHasView() {
                return Fragment.this.mView != null;
            }
        }, this);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void performCreate(Bundle savedInstanceState) {
        Parcelable p;
        if (this.mChildFragmentManager != null) {
            this.mChildFragmentManager.noteStateNotSaved();
        }
        this.mCalled = false;
        onCreate(savedInstanceState);
        if (!this.mCalled) {
            throw new SuperNotCalledException("Fragment " + this + " did not call through to super.onCreate()");
        }
        if (savedInstanceState != null && (p = savedInstanceState.getParcelable("android:support:fragments")) != null) {
            if (this.mChildFragmentManager == null) {
                instantiateChildFragmentManager();
            }
            this.mChildFragmentManager.restoreAllState(p, null);
            this.mChildFragmentManager.dispatchCreate();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public View performCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        if (this.mChildFragmentManager != null) {
            this.mChildFragmentManager.noteStateNotSaved();
        }
        return onCreateView(inflater, container, savedInstanceState);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void performActivityCreated(Bundle savedInstanceState) {
        if (this.mChildFragmentManager != null) {
            this.mChildFragmentManager.noteStateNotSaved();
        }
        this.mCalled = false;
        onActivityCreated(savedInstanceState);
        if (!this.mCalled) {
            throw new SuperNotCalledException("Fragment " + this + " did not call through to super.onActivityCreated()");
        }
        if (this.mChildFragmentManager != null) {
            this.mChildFragmentManager.dispatchActivityCreated();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void performStart() {
        if (this.mChildFragmentManager != null) {
            this.mChildFragmentManager.noteStateNotSaved();
            this.mChildFragmentManager.execPendingActions();
        }
        this.mCalled = false;
        onStart();
        if (!this.mCalled) {
            throw new SuperNotCalledException("Fragment " + this + " did not call through to super.onStart()");
        }
        if (this.mChildFragmentManager != null) {
            this.mChildFragmentManager.dispatchStart();
        }
        if (this.mLoaderManager != null) {
            this.mLoaderManager.doReportStart();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void performResume() {
        if (this.mChildFragmentManager != null) {
            this.mChildFragmentManager.noteStateNotSaved();
            this.mChildFragmentManager.execPendingActions();
        }
        this.mCalled = false;
        onResume();
        if (!this.mCalled) {
            throw new SuperNotCalledException("Fragment " + this + " did not call through to super.onResume()");
        }
        if (this.mChildFragmentManager != null) {
            this.mChildFragmentManager.dispatchResume();
            this.mChildFragmentManager.execPendingActions();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void performConfigurationChanged(Configuration newConfig) {
        onConfigurationChanged(newConfig);
        if (this.mChildFragmentManager != null) {
            this.mChildFragmentManager.dispatchConfigurationChanged(newConfig);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void performLowMemory() {
        onLowMemory();
        if (this.mChildFragmentManager != null) {
            this.mChildFragmentManager.dispatchLowMemory();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean performCreateOptionsMenu(Menu menu, MenuInflater inflater) {
        boolean show = false;
        if (this.mHidden) {
            return false;
        }
        if (this.mHasMenu && this.mMenuVisible) {
            show = true;
            onCreateOptionsMenu(menu, inflater);
        }
        if (this.mChildFragmentManager != null) {
            return show | this.mChildFragmentManager.dispatchCreateOptionsMenu(menu, inflater);
        }
        return show;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean performPrepareOptionsMenu(Menu menu) {
        boolean show = false;
        if (this.mHidden) {
            return false;
        }
        if (this.mHasMenu && this.mMenuVisible) {
            show = true;
            onPrepareOptionsMenu(menu);
        }
        if (this.mChildFragmentManager != null) {
            return show | this.mChildFragmentManager.dispatchPrepareOptionsMenu(menu);
        }
        return show;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean performOptionsItemSelected(MenuItem item) {
        if (!this.mHidden) {
            if (this.mHasMenu && this.mMenuVisible && onOptionsItemSelected(item)) {
                return true;
            }
            if (this.mChildFragmentManager != null && this.mChildFragmentManager.dispatchOptionsItemSelected(item)) {
                return true;
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean performContextItemSelected(MenuItem item) {
        if (!this.mHidden) {
            if (onContextItemSelected(item)) {
                return true;
            }
            if (this.mChildFragmentManager != null && this.mChildFragmentManager.dispatchContextItemSelected(item)) {
                return true;
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void performOptionsMenuClosed(Menu menu) {
        if (!this.mHidden) {
            if (this.mHasMenu && this.mMenuVisible) {
                onOptionsMenuClosed(menu);
            }
            if (this.mChildFragmentManager != null) {
                this.mChildFragmentManager.dispatchOptionsMenuClosed(menu);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void performSaveInstanceState(Bundle outState) {
        Parcelable p;
        onSaveInstanceState(outState);
        if (this.mChildFragmentManager != null && (p = this.mChildFragmentManager.saveAllState()) != null) {
            outState.putParcelable("android:support:fragments", p);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void performPause() {
        if (this.mChildFragmentManager != null) {
            this.mChildFragmentManager.dispatchPause();
        }
        this.mCalled = false;
        onPause();
        if (!this.mCalled) {
            throw new SuperNotCalledException("Fragment " + this + " did not call through to super.onPause()");
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void performStop() {
        if (this.mChildFragmentManager != null) {
            this.mChildFragmentManager.dispatchStop();
        }
        this.mCalled = false;
        onStop();
        if (!this.mCalled) {
            throw new SuperNotCalledException("Fragment " + this + " did not call through to super.onStop()");
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void performReallyStop() {
        if (this.mChildFragmentManager != null) {
            this.mChildFragmentManager.dispatchReallyStop();
        }
        if (this.mLoadersStarted) {
            this.mLoadersStarted = false;
            if (!this.mCheckedForLoaderManager) {
                this.mCheckedForLoaderManager = true;
                this.mLoaderManager = this.mHost.getLoaderManager(this.mWho, this.mLoadersStarted, false);
            }
            if (this.mLoaderManager != null) {
                if (this.mRetainLoader) {
                    this.mLoaderManager.doRetain();
                } else {
                    this.mLoaderManager.doStop();
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void performDestroyView() {
        if (this.mChildFragmentManager != null) {
            this.mChildFragmentManager.dispatchDestroyView();
        }
        this.mCalled = false;
        onDestroyView();
        if (!this.mCalled) {
            throw new SuperNotCalledException("Fragment " + this + " did not call through to super.onDestroyView()");
        }
        if (this.mLoaderManager != null) {
            this.mLoaderManager.doReportNextStart();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void performDestroy() {
        if (this.mChildFragmentManager != null) {
            this.mChildFragmentManager.dispatchDestroy();
        }
        this.mCalled = false;
        onDestroy();
        if (!this.mCalled) {
            throw new SuperNotCalledException("Fragment " + this + " did not call through to super.onDestroy()");
        }
    }
}
