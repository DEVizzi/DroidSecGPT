package com.google.android.gms.dynamic;

import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.View;
import com.google.android.gms.dynamic.zzc;
/* loaded from: classes.dex */
public final class zzh extends zzc.zza {
    private Fragment zzZX;

    private zzh(Fragment fragment) {
        this.zzZX = fragment;
    }

    public static zzh zza(Fragment fragment) {
        if (fragment != null) {
            return new zzh(fragment);
        }
        return null;
    }

    @Override // com.google.android.gms.dynamic.zzc
    public Bundle getArguments() {
        return this.zzZX.getArguments();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public int getId() {
        return this.zzZX.getId();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public boolean getRetainInstance() {
        return this.zzZX.getRetainInstance();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public String getTag() {
        return this.zzZX.getTag();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public int getTargetRequestCode() {
        return this.zzZX.getTargetRequestCode();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public boolean getUserVisibleHint() {
        return this.zzZX.getUserVisibleHint();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public zzd getView() {
        return zze.zzw(this.zzZX.getView());
    }

    @Override // com.google.android.gms.dynamic.zzc
    public boolean isAdded() {
        return this.zzZX.isAdded();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public boolean isDetached() {
        return this.zzZX.isDetached();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public boolean isHidden() {
        return this.zzZX.isHidden();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public boolean isInLayout() {
        return this.zzZX.isInLayout();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public boolean isRemoving() {
        return this.zzZX.isRemoving();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public boolean isResumed() {
        return this.zzZX.isResumed();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public boolean isVisible() {
        return this.zzZX.isVisible();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public void setHasOptionsMenu(boolean hasMenu) {
        this.zzZX.setHasOptionsMenu(hasMenu);
    }

    @Override // com.google.android.gms.dynamic.zzc
    public void setMenuVisibility(boolean menuVisible) {
        this.zzZX.setMenuVisibility(menuVisible);
    }

    @Override // com.google.android.gms.dynamic.zzc
    public void setRetainInstance(boolean retain) {
        this.zzZX.setRetainInstance(retain);
    }

    @Override // com.google.android.gms.dynamic.zzc
    public void setUserVisibleHint(boolean isVisibleToUser) {
        this.zzZX.setUserVisibleHint(isVisibleToUser);
    }

    @Override // com.google.android.gms.dynamic.zzc
    public void startActivity(Intent intent) {
        this.zzZX.startActivity(intent);
    }

    @Override // com.google.android.gms.dynamic.zzc
    public void startActivityForResult(Intent intent, int requestCode) {
        this.zzZX.startActivityForResult(intent, requestCode);
    }

    @Override // com.google.android.gms.dynamic.zzc
    public void zzl(zzd zzdVar) {
        this.zzZX.registerForContextMenu((View) zze.zzn(zzdVar));
    }

    @Override // com.google.android.gms.dynamic.zzc
    public void zzm(zzd zzdVar) {
        this.zzZX.unregisterForContextMenu((View) zze.zzn(zzdVar));
    }

    @Override // com.google.android.gms.dynamic.zzc
    public zzd zzqk() {
        return zze.zzw(this.zzZX.getActivity());
    }

    @Override // com.google.android.gms.dynamic.zzc
    public zzc zzql() {
        return zza(this.zzZX.getParentFragment());
    }

    @Override // com.google.android.gms.dynamic.zzc
    public zzd zzqm() {
        return zze.zzw(this.zzZX.getResources());
    }

    @Override // com.google.android.gms.dynamic.zzc
    public zzc zzqn() {
        return zza(this.zzZX.getTargetFragment());
    }
}
