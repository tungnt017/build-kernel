#!/bin/bash
set -e
OPTIONAL=false
[ "$1" = "--optional" ] && OPTIONAL=true

insert_hook() {
    local FILE="$1" DESC="$2" PATTERN="$3" ANCHOR="$4" POS="$5"
    shift 5
    local CODE="$*"
    local KEY_LINE
    KEY_LINE=$(echo "$CODE" | grep -m1 'ksu_handle\|path_umount\|can_umount\|ksu_input_hook\|EXPORT_SYMBOL' || echo "KSU_MANUAL_HOOK")
    KEY_LINE=$(echo "$KEY_LINE" | sed 's/^[[:space:]]*//')
    if grep -qF "$KEY_LINE" "$FILE" 2>/dev/null; then
        echo "  ⏭️  $DESC — already present, skipping"
        return 0
    fi
    local TMP="${FILE}.tmp"
    awk -v pattern="$PATTERN" -v anchor="$ANCHOR" -v code="$CODE" -v pos="$POS" '
    BEGIN { found_fn=0; done_insert=0 }
    {
        if (!done_insert && index($0, pattern) > 0) { found_fn=1 }
        if (found_fn && !done_insert && index($0, anchor) > 0) {
            n = split(code, lines, "\n")
            if (pos == "before") { for (i=1; i<=n; i++) print lines[i]; print }
            else { print; for (i=1; i<=n; i++) print lines[i] }
            done_insert=1; found_fn=0; next
        }
        print
    }
    ' "$FILE" > "$TMP"
    if [ -s "$TMP" ]; then mv "$TMP" "$FILE"; echo "  ✅ $DESC"
    else echo "  ❌ $DESC — failed"; rm -f "$TMP"; return 1; fi
}

echo ""
echo "═══════════════════════════════════════════════════════"
echo "🪝 Applying ReSukiSU manual hooks"
echo "═══════════════════════════════════════════════════════"

echo ""
echo "📄 fs/stat.c"
insert_hook "fs/stat.c" "stat: extern declarations" "#if !defined(__ARCH_WANT_STAT64)" "#if !defined(__ARCH_WANT_STAT64)" "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_stat(int *dfd, const char __user **filename_user,
				int *flags);
extern void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
extern void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf_ptr);
#endif
#endif
'
insert_hook "fs/stat.c" "stat: hook newfstatat" "SYSCALL_DEFINE4(newfstatat," "int error;" "after" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_stat(&dfd, &filename, &flag);
#endif'
insert_hook "fs/stat.c" "stat: hook newfstat_ret" "SYSCALL_DEFINE2(newfstat," "return error;" "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_newfstat_ret(&fd, &statbuf);
#endif'
insert_hook "fs/stat.c" "stat: hook fstatat64" "SYSCALL_DEFINE4(fstatat64," "int error;" "after" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_stat(&dfd, &filename, &flag);
#endif'
insert_hook "fs/stat.c" "stat: hook fstat64_ret" "SYSCALL_DEFINE2(fstat64," "return error;" "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_fstat64_ret(&fd, &statbuf);
#endif'

echo ""
echo "📄 fs/exec.c"
insert_hook "fs/exec.c" "execve: extern" "int do_execve(" "int do_execve(" "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,
				void *argv, void *envp, int *flags);
#endif
'
insert_hook "fs/exec.c" "execve: do_execve" "int do_execve(" "struct user_arg_ptr envp" "after" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
#endif'
insert_hook "fs/exec.c" "execve: compat" "compat_do_execve(" "return do_execveat_common" "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
#endif'

echo ""
echo "📄 fs/open.c"
insert_hook "fs/open.c" "faccessat: extern" "SYSCALL_DEFINE3(faccessat," "SYSCALL_DEFINE3(faccessat," "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
				int *mode, int *flags);
#endif
'
insert_hook "fs/open.c" "faccessat: hook" "SYSCALL_DEFINE3(faccessat," "return do_faccessat" "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
#endif'

echo ""
echo "📄 kernel/reboot.c"
insert_hook "kernel/reboot.c" "reboot: extern" "SYSCALL_DEFINE4(reboot," "SYSCALL_DEFINE4(reboot," "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);
#endif
'
insert_hook "kernel/reboot.c" "reboot: hook" "SYSCALL_DEFINE4(reboot," "int ret = 0;" "after" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
#endif'

# ──────────────────────────────────────────────────
# REQUIRED: path_umount backport + EXPORT_SYMBOL
# ──────────────────────────────────────────────────
echo ""
echo "📄 fs/namespace.c (path_umount — REQUIRED)"
if ! grep -q "int path_umount" "fs/namespace.c" 2>/dev/null; then
    insert_hook "fs/namespace.c" "path_umount backport" "Now umount can handle mount points" "Now umount can handle mount points" "before" \
'static int can_umount(const struct path *path, int flags)
{
	struct mount *mnt = real_mount(path->mnt);
	if (flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW))
		return -EINVAL;
	if (!may_mount())
		return -EPERM;
	if (path->dentry != path->mnt->mnt_root)
		return -EINVAL;
	if (!check_mnt(mnt))
		return -EINVAL;
	if (mnt->mnt.mnt_flags & MNT_LOCKED)
		return -EINVAL;
	if (flags & MNT_FORCE && !capable(CAP_SYS_ADMIN))
		return -EPERM;
	return 0;
}

int path_umount(struct path *path, int flags)
{
	struct mount *mnt = real_mount(path->mnt);
	int ret;
	ret = can_umount(path, flags);
	if (!ret)
		ret = do_umount(mnt, flags);
	dput(path->dentry);
	mntput_no_expire(mnt);
	return ret;
}
EXPORT_SYMBOL(path_umount);
'
else
    echo "  ⏭️  path_umount function exists"
    if ! grep -q "EXPORT_SYMBOL(path_umount)" "fs/namespace.c"; then
        # Add EXPORT_SYMBOL after closing brace of path_umount
        awk 'BEGIN{in_func=0;done=0} /^int path_umount/{in_func=1} in_func&&!done&&/^}/{print;print "EXPORT_SYMBOL(path_umount);";in_func=0;done=1;next} {print}' \
            "fs/namespace.c" > "fs/namespace.c.tmp" && mv "fs/namespace.c.tmp" "fs/namespace.c"
        echo "  ✅ Added EXPORT_SYMBOL(path_umount)"
    fi
fi

# Optional: input hook
if [ "$OPTIONAL" = true ]; then
    echo ""
    echo "📄 drivers/input/input.c (optional)"
    insert_hook "drivers/input/input.c" "input: extern" "void input_event(" "void input_event(" "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
extern bool ksu_input_hook __read_mostly;
extern __attribute__((cold)) int ksu_handle_input_handle_event(
			unsigned int *type, unsigned int *code, int *value);
#endif
'
    insert_hook "drivers/input/input.c" "input: hook" "void input_event(" "unsigned long flags;" "after" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
	if (unlikely(ksu_input_hook))
		ksu_handle_input_handle_event(&type, &code, &value);
#endif'
fi

# VERIFY
echo ""
echo "═══════════════════════════════════════════════════════"
echo "🔍 Verifying hooks..."
echo "═══════════════════════════════════════════════════════"
ALL_OK=true
check_hook() {
    local FILE="$1" FUNC="$2"
    local count
    count=$(grep -c "$FUNC" "$FILE" 2>/dev/null || echo "0")
    if [ "$count" -ge 2 ]; then echo "  ✅ $FILE — $FUNC ($count)"
    elif [ "$count" -eq 1 ]; then echo "  ⚠️  $FILE — $FUNC (1)"
    else echo "  ❌ $FILE — $FUNC NOT FOUND!"; ALL_OK=false; fi
}
check_hook "fs/stat.c"       "ksu_handle_stat"
check_hook "fs/stat.c"       "ksu_handle_newfstat_ret"
check_hook "fs/stat.c"       "ksu_handle_fstat64_ret"
check_hook "fs/exec.c"       "ksu_handle_execveat"
check_hook "fs/open.c"       "ksu_handle_faccessat"
check_hook "kernel/reboot.c" "ksu_handle_sys_reboot"
check_hook "fs/namespace.c"  "path_umount"
check_hook "fs/namespace.c"  "EXPORT_SYMBOL(path_umount)"
if [ "$OPTIONAL" = true ]; then
    check_hook "drivers/input/input.c" "ksu_handle_input_handle_event"
fi
echo ""
if [ "$ALL_OK" = true ]; then echo "✅ All hooks verified!"
else echo "❌ Some hooks failed!"; exit 1; fi
