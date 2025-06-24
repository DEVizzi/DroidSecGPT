.class Lcom/android/insecurebankv2/FilePrefActivity$1;
.super Ljava/lang/Object;
.source "FilePrefActivity.java"

# interfaces
.implements Landroid/view/View$OnClickListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/android/insecurebankv2/FilePrefActivity;->onCreate(Landroid/os/Bundle;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lcom/android/insecurebankv2/FilePrefActivity;


# direct methods
.method constructor <init>(Lcom/android/insecurebankv2/FilePrefActivity;)V
    .locals 0
    .param p1, "this$0"    # Lcom/android/insecurebankv2/FilePrefActivity;

    .prologue
    .line 45
    iput-object p1, p0, Lcom/android/insecurebankv2/FilePrefActivity$1;->this$0:Lcom/android/insecurebankv2/FilePrefActivity;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onClick(Landroid/view/View;)V
    .locals 1
    .param p1, "v"    # Landroid/view/View;

    .prologue
    .line 49
    iget-object v0, p0, Lcom/android/insecurebankv2/FilePrefActivity$1;->this$0:Lcom/android/insecurebankv2/FilePrefActivity;

    invoke-virtual {v0}, Lcom/android/insecurebankv2/FilePrefActivity;->setPreferences()V

    .line 50
    return-void
.end method
