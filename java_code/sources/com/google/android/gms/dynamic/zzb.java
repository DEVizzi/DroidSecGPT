package com.google.android.gms.dynamic;

import android.app.Fragment;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import com.google.android.gms.dynamic.zzc;
/* loaded from: classes.dex */
public final class zzb extends zzc.zza {
    private Fragment zzajt;

    private zzb(Fragment fragment) {
        this.zzajt = fragment;
    }

    public static zzb zza(Fragment fragment) {
        if (fragment != null) {
            return new zzb(fragment);
        }
        return null;
    }

    @Override // com.google.android.gms.dynamic.zzc
    public Bundle getArguments() {
        return this.zzajt.getArguments();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public int getId() {
        return this.zzajt.getId();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public boolean getRetainInstance() {
        return this.zzajt.getRetainInstance();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public String getTag() {
        return this.zzajt.getTag();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public int getTargetRequestCode() {
        return this.zzajt.getTargetRequestCode();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public boolean getUserVisibleHint() {
        return this.zzajt.getUserVisibleHint();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public zzd getView() {
        return zze.zzw(this.zzajt.getView());
    }

    @Override // com.google.android.gms.dynamic.zzc
    public boolean isAdded() {
        return this.zzajt.isAdded();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public boolean isDetached() {
        return this.zzajt.isDetached();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public boolean isHidden() {
        return this.zzajt.isHidden();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public boolean isInLayout() {
        return this.zzajt.isInLayout();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public boolean isRemoving() {
        return this.zzajt.isRemoving();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public boolean isResumed() {
        return this.zzajt.isResumed();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public boolean isVisible() {
        return this.zzajt.isVisible();
    }

    @Override // com.google.android.gms.dynamic.zzc
    public void setHasOptionsMenu(boolean hasMenu) {
        this.zzajt.setHasOptionsMenu(hasMenu);
    }

    @Override // com.google.android.gms.dynamic.zzc
    public void setMenuVisibility(boolean menuVisible) {
        this.zzajt.setMenuVisibility(menuVisible);
    }

    @Override // com.google.android.gms.dynamic.zzc
    public void setRetainInstance(boolean retain) {
        this.zzajt.setRetainInstance(retain);
    }

    @Override // com.google.android.gms.dynamic.zzc
    public void setUserVisibleHint(boolean isVisibleToUser) {
        this.zzajt.setUserVisibleHint(isVisibleToUser);
    }

    @Override // com.google.android.gms.dynamic.zzc
    public void startActivity(Intent intent) {
        this.zzajt.startActivity(intent);
    }

    @Override // com.google.android.gms.dynamic.zzc
    public void startActivityForResult(Intent intent, int requestCode) {
        this.zzajt.startActivityForResult(intent, requestCode);
    }

    @Override // com.google.android.gms.dynamic.zzc
    public void zzl(zzd zzdVar) {
        this.zzajt.registerForContextMenu((View) zze.zzn(zzdVar));
    }

    @Override // com.google.android.gms.dynamic.zzc
    public void zzm(zzd zzdVar) {
        this.zzajt.unregisterForContextMenu((View) zze.zzn(zzdVar));
    }

    @Override // com.google.android.gms.dynamic.zzc
    public zzd zzqk() {
        return zze.zzw(this.zzajt.getActivity());
    }

    @Override // com.google.android.gms.dynamic.zzc
    public zzc zzql() {
        return zza(this.zzajt.getParentFragment());
    }

    @Override // com.google.android.gms.dynamic.zzc
    public zzd zzqm() {
        return zze.zzw(this.zzajt.getResources());
    }

    @Override // com.google.android.gms.dynamic.zzc
    public zzc zzqn() {
        return zza(this.zzajt.getTargetFragment());
    }
}
