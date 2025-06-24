.class public abstract Landroid/support/v7/media/RemotePlaybackClient$ItemActionCallback;
.super Landroid/support/v7/media/RemotePlaybackClient$ActionCallback;
.source "RemotePlaybackClient.java"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroid/support/v7/media/RemotePlaybackClient;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x409
    name = "ItemActionCallback"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .prologue
    .line 903
    invoke-direct {p0}, Landroid/support/v7/media/RemotePlaybackClient$ActionCallback;-><init>()V

    return-void
.end method


# virtual methods
.method public onResult(Landroid/os/Bundle;Ljava/lang/String;Landroid/support/v7/media/MediaSessionStatus;Ljava/lang/String;Landroid/support/v7/media/MediaItemStatus;)V
    .locals 0
    .param p1, "data"    # Landroid/os/Bundle;
    .param p2, "sessionId"    # Ljava/lang/String;
    .param p3, "sessionStatus"    # Landroid/support/v7/media/MediaSessionStatus;
    .param p4, "itemId"    # Ljava/lang/String;
    .param p5, "itemStatus"    # Landroid/support/v7/media/MediaItemStatus;

    .prologue
    .line 915
    return-void
.end method
