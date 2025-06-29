package android.support.design.internal;

import android.content.Context;
import android.support.v7.internal.view.menu.MenuBuilder;
import android.support.v7.internal.view.menu.MenuItemImpl;
import android.support.v7.internal.view.menu.SubMenuBuilder;
import android.view.MenuItem;
/* loaded from: classes.dex */
public class NavigationSubMenu extends SubMenuBuilder {
    public NavigationSubMenu(Context context, NavigationMenu menu, MenuItemImpl item) {
        super(context, menu, item);
    }

    @Override // android.support.v7.internal.view.menu.MenuBuilder, android.view.Menu
    public MenuItem add(CharSequence title) {
        MenuItem item = super.add(title);
        notifyParent();
        return item;
    }

    @Override // android.support.v7.internal.view.menu.MenuBuilder, android.view.Menu
    public MenuItem add(int titleRes) {
        MenuItem item = super.add(titleRes);
        notifyParent();
        return item;
    }

    @Override // android.support.v7.internal.view.menu.MenuBuilder, android.view.Menu
    public MenuItem add(int groupId, int itemId, int order, CharSequence title) {
        MenuItem item = super.add(groupId, itemId, order, title);
        notifyParent();
        return item;
    }

    @Override // android.support.v7.internal.view.menu.MenuBuilder, android.view.Menu
    public MenuItem add(int groupId, int itemId, int order, int titleRes) {
        MenuItem item = super.add(groupId, itemId, order, titleRes);
        notifyParent();
        return item;
    }

    private void notifyParent() {
        ((MenuBuilder) getParentMenu()).onItemsChanged(true);
    }
}
