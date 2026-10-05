/* Demo.exe - the target program used by EIP's examples and tests.
 *
 * Exposes exactly the two scenarios from the spec:
 *   1. Player.RunSpeed: an exported int, starts at 10. EIP changes it to 20.
 *   2. A menu (Open/Save/Exit) backed by a fixed-size exported array plus an
 *      exported count. EIP adds "Export" as a brand new item by writing the
 *      string into an already-reserved-but-unused slot and bumping the count -
 *      a real new feature appearing in a program that never shipped with it,
 *      with no process restart required.
 *
 * Built as a plain console EXE (not -mwindows) so it runs under any test
 * harness and its exports are visible with a normal PE export table.
 */
#include <stdio.h>
#include <string.h>
#include <windows.h>

/* --- Scenario 1: a value EIP will change at runtime --------------------- */
__declspec(dllexport) int g_RunSpeed = 10;

__declspec(dllexport) int GetRunSpeed(void) {
    return g_RunSpeed;
}

/* --- Scenario 2: a menu EIP will extend with a feature that never shipped */
#define MENU_CAPACITY 8
#define MENU_ITEM_LEN 16

__declspec(dllexport) int g_MenuCount = 3;
__declspec(dllexport) char g_MenuItems[MENU_CAPACITY][MENU_ITEM_LEN] = {
    "Open", "Save", "Exit", "", "", "", "", ""
};

__declspec(dllexport) void PrintMenu(void) {
    int i;
    for (i = 0; i < g_MenuCount; i++) {
        printf("%s\n", g_MenuItems[i]);
    }
}

int main(int argc, char** argv) {
    int tick;
    (void)argc; (void)argv;

    printf("Demo.exe started (pid visible via Task Manager / eip.process.find)\n");
    printf("RunSpeed = %d\n", GetRunSpeed());
    printf("--- menu ---\n");
    PrintMenu();

    /* Stay alive so EIP can attach to a real running process (a process
     * that already exited before `eip.attach()` runs cannot be attached
     * to). Reprints live state once a second so changes EIP makes
     * (RunSpeed, menu items) are visible without a debugger. Exits on its
     * own after ~5 minutes so it never becomes an orphaned background
     * process if a test script forgets to stop it. */
    for (tick = 0; tick < 300; tick++) {
        int i;
        printf("[%3d] RunSpeed=%d menu(%d)=", tick, GetRunSpeed(), g_MenuCount);
        for (i = 0; i < g_MenuCount; i++) {
            printf("%s%s", i ? "," : "", g_MenuItems[i]);
        }
        printf("\n");
        fflush(stdout);
        Sleep(1000);
    }
    return 0;
}
