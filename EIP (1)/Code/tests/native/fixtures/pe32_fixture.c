#include <windows.h>
__declspec(dllexport) int g_RunSpeed = 10;
int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR c, int n) { (void)h;(void)p;(void)c;(void)n; return g_RunSpeed; }
