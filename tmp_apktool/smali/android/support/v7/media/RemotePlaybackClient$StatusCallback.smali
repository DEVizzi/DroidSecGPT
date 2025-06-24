.class public abstract Landroid/support/v7/media/RemotePlaybackClient$StatusCallback;
.super Ljava/lang/Object;
.source "RemotePlaybackClient.java"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroid/support/v7/media/RemotePlaybackClient;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x409
    name = "StatusCallback"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .prologue
    .line 849
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onItemStatusChanged(Landroid/os/Bundle;Ljava/lang/String;Landroid/support/v7/media/MediaSessionStatus;Ljava/lang/String;Landroid/support/v7/media/MediaItemStatus;)V
    .locals 0
    .param p1, "data"    # Landroid/os/Bundle;
    .param p2, "sessionId"    # Ljava/lang/String;
    .param p3, "sessionStatus"    # Landroid/support/v7/media/MediaSessionStatus;
    .param p4, "itemId"    # Ljava/lang/String;
    .param p5, "itemStatus"    # Landroid/support/v7/media/MediaItemStatus;

    .prologue
    .line 862
    return-void
.end method

.method public onSessionChanged(Ljava/lang/String;)V
    .locals 0
    .param p1, "sessionId"    # Ljava/lang/String;

    .prologue
    .line 881
    return-void
.end method

.method public onSessionStatusChanged(Landroid/os/Bundle;Ljava/lang/String;Landroid/support/v7/media/MediaSessionStatus;)V
    .locals 0
    .param p1, "data"    # Landroid/os/Bundle;
    .param p2, "sessionId"    # Ljava/lang/String;
    .param p3, "sessionStatus"    # Landroid/support/v7/media/MediaSessionStatus;

    .prologue
    .line 873
    return-void
.end method
