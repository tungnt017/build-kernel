#!/bin/bash
# apply_hooks.sh — Insert all ReSukiSU manual hooks via awk
# Usage: ./apply_hooks.sh [--optional]
#   --optional: also apply input_hook + path_umount
set -e

OPTIONAL=false
[ "$1" = "--optional" ] && OPTIONAL=true

insert_hook() {
    local FILE="$1" DESC="$2" PATTERN="$3" ANCHOR="$4" POS="$5" CODE="$6"
    if grep -q "CONFIG_KSU_MANUAL_HOOK" "$FILE" 2>/dev/null && \
       echo "$CODE" | head -3 | grep -qF "$(echo "$CODE" | sed -n '2p' | sed 's/^[ \t]*//')" && \
       grep -qF "$(echo "$CODE" | sed -n '2p' | sed 's/^[ \t]*//')" "$FILE"; then
        echo "  ⏭️  $DESC — already present, skipping"
        return 0
    fi

    local TMP="${FILE}.tmp"
    if [ "$POS" = "before" ]; then
        awk -v pattern="$PATTERN" -v anchor="$ANCHOR" -v code="$CODE" '
        BEGIN { found_fn=0; done_insert=0 }
        $0 ~ pattern { found_fn=1 }
        found_fn && !done_insert && $0 ~ anchor {
            n = split(code, lines, "\n")
            for (i=1; i<=n; i++) print lines[i]
            done_insert=1; found_fn=0
        }
        { print }
        ' "$FILE" > "$TMP"
    else
        awk -v pattern="$PATTERN" -v anchor="$ANCHOR" -v code="$CODE" '
        BEGIN { found_fn=0; done_insert=0 }
        $0 ~ pattern { found_fn=1 }
        found_fn && !done_insert && $0 ~ anchor {
            print
            n = split(code, lines, "\n")
            for (i=1; i<=n; i++) print lines[i]
            done_insert=1; found_fn=0
            next
        }
        { print }
        ' "$FILE" > "$TMP"
    fi

    if [ -s "$TMP" ]; then
        mv "$TMP" "$FILE"
        echo "  ✅ $DESC"
    else
        echo "  ❌ $DESC — awk produced empty output!"
        rm -f "$TMP"
        return 1
    fi
}

echo ""
echo "═══════════════════════════════════════════════════════"
echo "🪝 Applying ReSukiSU manual hooks via awk"
echo "═══════════════════════════════════════════════════════"

# ──────────────────────────────────────────────────
# 1. fs/stat.c
# ──────────────────────────────────────────────────
echo ""
echo "📄 fs/stat.c"

# 1a. Extern declarations — insert after newlstat closing brace, before the #if !defined block
insert_hook "fs/stat.c" \
    "stat: extern declarations" \
    "#if !defined\\(__ARCH_WANT_STAT64\\)" \
    "#if !defined\\(__ARCH_WANT_STAT64\\)" \
    "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_stat(int *dfd, const char __user **filename_user,
\t\t\t\tint *flags);
extern void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
extern void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf_ptr);
#endif
#endif
'

# 1b. Hook in SYSCALL_DEFINE4(newfstatat) — insert after "int error;"
insert_hook "fs/stat.c" \
    "stat: hook in newfstatat" \
    "SYSCALL_DEFINE4\\(newfstatat," \
    "int error;" \
    "after" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
\tksu_handle_stat(&dfd, &filename, &flag);
#endif'

# 1c. Hook in SYSCALL_DEFINE2(newfstat) — insert before "return error;"
insert_hook "fs/stat.c" \
    "stat: hook newfstat_ret" \
    "SYSCALL_DEFINE2\\(newfstat," \
    "return error;" \
    "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
\tksu_handle_newfstat_ret(&fd, &statbuf);
#endif'

# 1d. Hook in SYSCALL_DEFINE4(fstatat64) — insert after "int error;"
insert_hook "fs/stat.c" \
    "stat: hook in fstatat64" \
    "SYSCALL_DEFINE4\\(fstatat64," \
    "int error;" \
    "after" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
\tksu_handle_stat(&dfd, &filename, &flag);
#endif'

# 1e. Hook in SYSCALL_DEFINE2(fstat64) — insert before "return error;"
insert_hook "fs/stat.c" \
    "stat: hook fstat64_ret" \
    "SYSCALL_DEFINE2\\(fstat64," \
    "return error;" \
    "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
\tksu_handle_fstat64_ret(&fd, &statbuf);
#endif'

# ──────────────────────────────────────────────────
# 2. fs/exec.c
# ──────────────────────────────────────────────────
echo ""
echo "📄 fs/exec.c"

# 2a. Extern declaration — insert before "int do_execve("
insert_hook "fs/exec.c" \
    "execve: extern declaration" \
    "^int do_execve\\(" \
    "^int do_execve\\(" \
    "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,
\t\t\t\tvoid *argv, void *envp, int *flags);
#endif
'

# 2b. Hook in do_execve — insert after "struct user_arg_ptr envp"
insert_hook "fs/exec.c" \
    "execve: hook in do_execve" \
    "^int do_execve\\(" \
    "struct user_arg_ptr envp" \
    "after" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
\tksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
#endif'

# 2c. Hook in compat_do_execve — insert before "return do_execveat_common"
insert_hook "fs/exec.c" \
    "execve: hook in compat_do_execve" \
    "compat_do_execve\\(" \
    "return do_execveat_common" \
    "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
\tksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
#endif'

# ──────────────────────────────────────────────────
# 3. fs/open.c
# ──────────────────────────────────────────────────
echo ""
echo "📄 fs/open.c"

# 3a. Extern declaration — insert before SYSCALL_DEFINE3(faccessat
insert_hook "fs/open.c" \
    "faccessat: extern declaration" \
    "SYSCALL_DEFINE3\\(faccessat," \
    "SYSCALL_DEFINE3\\(faccessat," \
    "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
\t\t\t\tint *mode, int *flags);
#endif
'

# 3b. Hook in SYSCALL_DEFINE3(faccessat) — insert before "return do_faccessat"
insert_hook "fs/open.c" \
    "faccessat: hook call" \
    "SYSCALL_DEFINE3\\(faccessat," \
    "return do_faccessat" \
    "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);
#endif'

# ──────────────────────────────────────────────────
# 4. kernel/reboot.c
# ──────────────────────────────────────────────────
echo ""
echo "📄 kernel/reboot.c"

# 4a. Extern declaration — insert before SYSCALL_DEFINE4(reboot
insert_hook "kernel/reboot.c" \
    "reboot: extern declaration" \
    "SYSCALL_DEFINE4\\(reboot," \
    "SYSCALL_DEFINE4\\(reboot," \
    "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);
#endif
'

# 4b. Hook in SYSCALL_DEFINE4(reboot) — insert after "int ret = 0;"
insert_hook "kernel/reboot.c" \
    "reboot: hook call" \
    "SYSCALL_DEFINE4\\(reboot," \
    "int ret = 0;" \
    "after" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
\tksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
#endif'

# ──────────────────────────────────────────────────
# 5. Optional: drivers/input/input.c
# ──────────────────────────────────────────────────
if [ "$OPTIONAL" = true ]; then
    echo ""
    echo "📄 drivers/input/input.c (optional)"

    insert_hook "drivers/input/input.c" \
        "input: extern declarations" \
        "^void input_event\\(" \
        "^void input_event\\(" \
        "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
extern bool ksu_input_hook __read_mostly;
extern __attribute__((cold)) int ksu_handle_input_handle_event(
\t\t\tunsigned int *type, unsigned int *code, int *value);
#endif
'

    insert_hook "drivers/input/input.c" \
        "input: hook call" \
        "^void input_event\\(" \
        "unsigned long flags;" \
        "after" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
\tif (unlikely(ksu_input_hook))
\t\tksu_handle_input_handle_event(&type, &code, &value);
#endif'

    # 6. Optional: fs/namespace.c — path_umount backport
    echo ""
    echo "📄 fs/namespace.c (optional)"

    if ! grep -q "path_umount" "fs/namespace.c" 2>/dev/null; then
        insert_hook "fs/namespace.c" \
            "namespace: path_umount backport" \
            "Now umount can handle mount points" \
            "Now umount can handle mount points" \
            "before" \
'static int can_umount(const struct path *path, int flags)
{
\tstruct mount *mnt = real_mount(path->mnt);
\tif (flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW))
\t\treturn -EINVAL;
\tif (!may_mount())
\t\treturn -EPERM;
\tif (path->dentry != path->mnt->mnt_root)
\t\treturn -EINVAL;
\tif (!check_mnt(mnt))
\t\treturn -EINVAL;
\tif (mnt->mnt.mnt_flags & MNT_LOCKED)
\t\treturn -EINVAL;
\tif (flags & MNT_FORCE && !capable(CAP_SYS_ADMIN))
\t\treturn -EPERM;
\treturn 0;
}

int path_umount(struct path *path, int flags)
{
\tstruct mount *mnt = real_mount(path->mnt);
\tint ret;
\tret = can_umount(path, flags);
\tif (!ret)
\t\tret = do_umount(mnt, flags);
\tdput(path->dentry);
\tmntput_no_expire(mnt);
\treturn ret;
}
'
    else
        echo "  ⏭️  path_umount already exists"
    fi
fi

# ──────────────────────────────────────────────────
# VERIFICATION
# ──────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════"
echo "🔍 Verifying all hooks..."
echo "═══════════════════════════════════════════════════════"

ALL_OK=true
check_hook() {
    local FILE="$1" FUNC="$2"
    local count
    count=$(grep -c "$FUNC" "$FILE" 2>/dev/null || echo "0")
    if [ "$count" -ge 2 ]; then
        echo "  ✅ $FILE — $FUNC ($count occurrences)"
    elif [ "$count" -eq 1 ]; then
        echo "  ⚠️  $FILE — $FUNC (1 occurrence)"
    else
        echo "  ❌ $FILE — $FUNC NOT FOUND!"
        ALL_OK=false
    fi
}

check_hook "fs/stat.c"       "ksu_handle_stat"
check_hook "fs/stat.c"       "ksu_handle_newfstat_ret"
check_hook "fs/stat.c"       "ksu_handle_fstat64_ret"
check_hook "fs/exec.c"       "ksu_handle_execveat"
check_hook "fs/open.c"       "ksu_handle_faccessat"
check_hook "kernel/reboot.c" "ksu_handle_sys_reboot"

if [ "$OPTIONAL" = true ]; then
    check_hook "drivers/input/input.c" "ksu_handle_input_handle_event"
    check_hook "fs/namespace.c"        "path_umount"
fi

echo ""
if [ "$ALL_OK" = true ]; then
    echo "✅ All hooks verified successfully!"
else
    echo "❌ Some hooks failed! Check output above."
    exit 1
fi
