#!/bin/bash
set -e
OPTIONAL=false
[ "$1" = "--optional" ] && OPTIONAL=true

insert_hook() {
    local FILE="$1" DESC="$2" PATTERN="$3" ANCHOR="$4" POS="$5"
    shift 5
    local CODE="$*"
    local KEY_LINE
    KEY_LINE=$(echo "$CODE" | grep -m1 'ksu_handle\|path_umount\|can_umount\|ksu_input_hook' || echo "KSU_MANUAL_HOOK")
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
    else echo "  ❌ $DESC — awk produced empty output!"; rm -f "$TMP"; return 1; fi
}

echo ""
echo "═══════════════════════════════════════════════════════"
echo "🪝 Applying ReSukiSU manual hooks via awk"
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
insert_hook "fs/stat.c" "stat: hook in newfstatat" "SYSCALL_DEFINE4(newfstatat," "int error;" "after" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_stat(&dfd, &filename, &flag);
#endif'
insert_hook "fs/stat.c" "stat: hook newfstat_ret" "SYSCALL_DEFINE2(newfstat," "return error;" "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_newfstat_ret(&fd, &statbuf);
#endif'
insert_hook "fs/stat.c" "stat: hook in fstatat64" "SYSCALL_DEFINE4(fstatat64," "int error;" "after" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_stat(&dfd, &filename, &flag);
#endif'
insert_hook "fs/stat.c" "stat: hook fstat64_ret" "SYSCALL_DEFINE2(fstat64," "return error;" "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_fstat64_ret(&fd, &statbuf);
#endif'

echo ""
echo "📄 fs/exec.c"
insert_hook "fs/exec.c" "execve: extern declaration" "int do_execve(" "int do_execve(" "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,
				void *argv, void *envp, int *flags);
#endif
'
insert_hook "fs/exec.c" "execve: hook in do_execve" "int do_execve(" "struct user_arg_ptr envp" "after" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
#endif'
insert_hook "fs/exec.c" "execve: hook in compat_do_execve" "compat_do_execve(" "return do_execveat_common" "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
#endif'

echo ""
echo "📄 fs/open.c"
insert_hook "fs/open.c" "faccessat: extern declaration" "SYSCALL_DEFINE3(faccessat," "SYSCALL_DEFINE3(faccessat," "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
				int *mode, int *flags);
#endif
'
insert_hook "fs/open.c" "faccessat: hook call" "SYSCALL_DEFINE3(faccessat," "return do_faccessat" "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
#endif'

echo ""
echo "📄 kernel/reboot.c"
insert_hook "kernel/reboot.c" "reboot: extern declaration" "SYSCALL_DEFINE4(reboot," "SYSCALL_DEFINE4(reboot," "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);
#endif
'
insert_hook "kernel/reboot.c" "reboot: hook call" "SYSCALL_DEFINE4(reboot," "int ret = 0;" "after" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
#endif'

if [ "$OPTIONAL" = true ]; then
    echo ""
    echo "📄 drivers/input/input.c (optional)"
    insert_hook "drivers/input/input.c" "input: extern declarations" "void input_event(" "void input_event(" "before" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
extern bool ksu_input_hook __read_mostly;
extern __attribute__((cold)) int ksu_handle_input_handle_event(
			unsigned int *type, unsigned int *code, int *value);
#endif
'
    insert_hook "drivers/input/input.c" "input: hook call" "void input_event(" "unsigned long flags;" "after" \
'#ifdef CONFIG_KSU_MANUAL_HOOK
	if (unlikely(ksu_input_hook))
		ksu_handle_input_handle_event(&type, &code, &value);
#endif'

    echo ""
    echo "📄 fs/namespace.c (optional)"
    if ! grep -q "path_umount" "fs/namespace.c" 2>/dev/null; then
        insert_hook "fs/namespace.c" "namespace: path_umount backport" "Now umount can handle mount points" "Now umount can handle mount points" "before" \
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
'
    else
        echo "  ⏭️  path_umount already exists"
    fi
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "🔍 Verifying all hooks..."
echo "═══════════════════════════════════════════════════════"
ALL_OK=true
check_hook() {
    local FILE="$1" FUNC="$2"
    local count
    count=$(grep -c "$FUNC" "$FILE" 2>/dev/null || echo "0")
    if [ "$count" -ge 2 ]; then echo "  ✅ $FILE — $FUNC ($count occurrences)"
    elif [ "$count" -eq 1 ]; then echo "  ⚠️  $FILE — $FUNC (1 occurrence)"
    else echo "  ❌ $FILE — $FUNC NOT FOUND!"; ALL_OK=false; fi
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
if [ "$ALL_OK" = true ]; then echo "✅ All hooks verified successfully!"
else echo "❌ Some hooks failed!"; exit 1; fi
